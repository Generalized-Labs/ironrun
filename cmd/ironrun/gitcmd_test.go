package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/envset"
)

const zero40 = "0000000000000000000000000000000000000000"

func TestPushRange(t *testing.T) {
	// Branch deletion (zero LOCAL sha): nothing to scan — refuse loudly
	// rather than scanning garbage.
	if _, err := pushRange("refs/heads/old", zero40, "abc123"); err == nil {
		t.Fatal("pushRange accepted a branch deletion (zero local sha)")
	}
	// New branch (zero REMOTE sha): highest-risk push, must be scanned via
	// the new-branch heuristic — never skipped.
	args, err := pushRange("refs/heads/new", "def456", zero40)
	if err != nil {
		t.Fatalf("pushRange refused a new branch: %v", err)
	}
	if len(args) != 1 || !strings.Contains(args[0], "def456") {
		t.Fatalf("new branch did not get the new-branch scan range: %v", args)
	}
	// Normal update: old..new.
	args, err = pushRange("refs/heads/main", "def456", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 || args[0] != "abc123..def456" {
		t.Fatalf("wrong range for branch update: %v", args)
	}
}

type memStore map[string]string

func (m memStore) Name() string                       { return "mem" }
func (m memStore) Set(scope, key, value string) error { m[scope+"/"+key] = value; return nil }
func (m memStore) Get(scope, key string) (string, error) {
	return m[scope+"/"+key], nil
}
func (m memStore) Delete(scope, key string) error { delete(m, scope+"/"+key); return nil }
func (m memStore) DeleteScope(scope string) error { return nil }

// REGRESSION: the hooks matched whole diff text against the ACTIVE set only.
// A multi-line value never matched ('+' prefixes split it), a value from a
// non-active set was never checked, and removing a leaked value was blocked.
func TestHookScanAddedContentAllSets(t *testing.T) {
	m := &envset.Manager{Root: t.TempDir(), Store: memStore{}, Now: time.Now,
		Meta: envset.Metadata{Version: 2, Sets: map[string]envset.Set{}}}
	for _, set := range []string{"dev", "prod"} {
		if _, err := m.Ensure(set); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Use("dev"); err != nil {
		t.Fatal(err)
	}
	if err := m.Put("prod", "TLS_KEY", "TEST-SECRET-0000\nTEST-SECRET-0001"); err != nil {
		t.Fatal(err)
	}
	secrets, err := allSetSecrets(m)
	if err != nil {
		t.Fatal(err)
	}
	added := "diff --git a/key.txt b/key.txt\n--- /dev/null\n+++ b/key.txt\n@@ -0,0 +1,2 @@\n+TEST-SECRET-0000\n+TEST-SECRET-0001\n"
	if hits := hitsByAlias(secrets, addedContent(added)); len(hits) != 1 {
		t.Fatalf("multi-line value from a non-active set was not caught: %v", hits)
	}
	removed := "diff --git a/key.txt b/key.txt\n--- a/key.txt\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-TEST-SECRET-0000\n-TEST-SECRET-0001\n"
	if hits := hitsByAlias(secrets, addedContent(removed)); len(hits) != 0 {
		t.Fatalf("removing a leaked value was blocked: %v", hits)
	}
}

// A staged binary file must reach the scanner as bytes, even when
// .gitattributes marks it -diff.
func TestScanDiffFlagsExposeBinaryContent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	git := func(args ...string) []byte {
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return out
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("*.p12 -diff\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.p12"), []byte("\x00\x01TEST-SECRET-0000\x02"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	diff := git(append([]string{"diff", "--cached"}, scanDiffFlags...)...)
	if !strings.Contains(addedContent(string(diff)), "TEST-SECRET-0000") {
		t.Fatalf("binary content hidden from the scanner:\n%q", diff)
	}
}

func TestIsZeroSha(t *testing.T) {
	if !isZeroSha(zero40) {
		t.Fatal("all-zero sha not recognized")
	}
	if !isZeroSha("0000") {
		t.Fatal("short all-zero sha not recognized")
	}
	if isZeroSha("abc123") || isZeroSha("") {
		t.Fatal("false positive on non-zero/empty sha")
	}
}
