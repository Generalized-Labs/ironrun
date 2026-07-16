package access

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	return m
}

func TestLeaseLifecycleExpiryAndRevocation(t *testing.T) {
	m := testManager(t)
	now := m.now()
	request, err := m.CreateLeaseRequest("session-a", "dev", []string{"test", "deploy", "test"}, 30*time.Minute, "run tests")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize("session-a", "dev", "test"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pre-approval authorization = %v", err)
	}
	lease, err := m.ApproveLease(request.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize("session-a", "dev", "test"); err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize("session-a", "prod", "test"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-environment authorization = %v", err)
	}
	if err := m.Authorize("session-b", "dev", "test"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-session authorization = %v", err)
	}
	if err := m.Authorize("session-a", "dev", "unknown"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-command authorization = %v", err)
	}
	if err := m.Revoke(lease.ID, "session-b"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-session revoke = %v", err)
	}
	if err := m.Revoke(lease.ID, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize("session-a", "dev", "test"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked authorization = %v", err)
	}

	request, err = m.CreateLeaseRequest("session-a", "dev", []string{"test"}, time.Minute, "retry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveLease(request.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	if err := m.Authorize("session-a", "dev", "test"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired authorization = %v", err)
	}
}

func TestWorkspaceGrantPinsSessionEnvironmentAndLifecycle(t *testing.T) {
	m := testManager(t)
	now := m.now()
	request, err := m.CreateWorkspaceRequest("session-a", "dev", []string{"go", "test", "./..."}, 2*time.Hour, "agent development")
	if err != nil {
		t.Fatal(err)
	}
	// A second arbitrary command must not create another interruption for the
	// same agent/environment while the first request is pending.
	duplicate, err := m.CreateWorkspaceRequest("session-a", "dev", []string{"npm", "test"}, 2*time.Hour, "agent development")
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.ID != request.ID {
		t.Fatalf("workspace request was not deduplicated: %s != %s", duplicate.ID, request.ID)
	}
	if _, err := m.AuthorizeWorkspace("session-a", "dev"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pre-approval authorization = %v", err)
	}
	grant, err := m.ApproveWorkspace(request.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthorizeWorkspace("session-a", "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthorizeWorkspace("session-b", "dev"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-session authorization = %v", err)
	}
	if _, err := m.AuthorizeWorkspace("session-a", "prod"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-environment authorization = %v", err)
	}
	if err := m.PauseWorkspace(grant.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthorizeWorkspace("session-a", "dev"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("paused authorization = %v", err)
	}
	if _, err := m.ExtendWorkspace(grant.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := m.PauseWorkspace(grant.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthorizeWorkspace("session-a", "dev"); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeWorkspace(grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthorizeWorkspace("session-a", "dev"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked authorization = %v", err)
	}

	request, err = m.CreateWorkspaceRequest("session-a", "dev", []string{"go", "test"}, time.Minute, "retry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveWorkspace(request.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := m.AuthorizeWorkspace("session-a", "dev"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired authorization = %v", err)
	}
}

func TestSecretRequestContainsNoValueAndDeduplicates(t *testing.T) {
	m := testManager(t)
	first, err := m.CreateSecretRequest("session-a", "dev", "openai", "OPENAI_API_KEY", "tests need it")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.CreateSecretRequest("session-a", "dev", "openai", "OPENAI_API_KEY", "again")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("duplicate request ids = %s, %s", first.ID, second.ID)
	}
	data, err := os.ReadFile(m.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-secret") {
		t.Fatal("access state contains a secret value")
	}
	if _, err := m.FulfillSecret(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.FulfillSecret(first.ID); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second fulfill error = %v", err)
	}
}

func TestConcurrentRequestMutationsDoNotLoseRecords(t *testing.T) {
	m := testManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := m.CreateSecretRequest("session-a", "dev", "alias-"+string(rune('a'+i)), "KEY_"+string(rune('A'+i)), "concurrent")
			if err != nil {
				t.Errorf("request %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	requests, err := m.Requests()
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 12 {
		t.Fatalf("requests = %d, want 12", len(requests))
	}
}

func TestConcurrentSecretFulfillmentCommitsExactlyOnce(t *testing.T) {
	m := testManager(t)
	request, err := m.CreateSecretRequest("session-a", "dev", "openai", "OPENAI_API_KEY", "claim")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	commits := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.FulfillSecretWith(request.ID, func(Request) error {
				mu.Lock()
				commits++
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()
	if commits != 1 {
		t.Fatalf("storage commits = %d, want exactly 1", commits)
	}
}
