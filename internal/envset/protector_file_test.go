package envset

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/vault"
)

// newTestFileProtector points HOME at a temp directory so the protector writes
// its key material there rather than into the developer's real ~/.ironrun.
func newTestFileProtector(t *testing.T) fileProtector {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	p, err := newFileProtector()
	if err != nil {
		t.Fatalf("newFileProtector: %v", err)
	}
	return p
}

func TestFileProtectorRoundTripsKey(t *testing.T) {
	p := newTestFileProtector(t)

	const encoded = "c2VjcmV0LXJvb3Qta2V5LW1hdGVyaWFs"
	if err := p.Save("project-abc", encoded); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := p.Load("project-abc")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != encoded {
		t.Errorf("Load returned %q, want %q", got, encoded)
	}
}

func TestFileProtectorReportsMissingKeyDistinctly(t *testing.T) {
	p := newTestFileProtector(t)

	// vault.Open relies on this exact sentinel to decide between creating a
	// first key and failing closed on an existing vault. Any other error here
	// would turn a missing key into a hard failure on first use.
	_, err := p.Load("project-never-written")
	if !errors.Is(err, vault.ErrKeyMissing) {
		t.Fatalf("Load of absent key returned %v, want vault.ErrKeyMissing", err)
	}
}

func TestFileProtectorWritesOwnerOnlyPermissions(t *testing.T) {
	p := newTestFileProtector(t)

	if err := p.Save("project-perm", "a2V5"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(filepath.Join(p.dir, "project-perm.key"))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode is %04o, want 0600", perm)
	}

	dirInfo, err := os.Stat(p.dir)
	if err != nil {
		t.Fatalf("stat key dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("key directory mode is %04o, want 0700", perm)
	}
}

func TestFileProtectorRefusesGroupOrWorldReadableKey(t *testing.T) {
	p := newTestFileProtector(t)

	if err := p.Save("project-loose", "a2V5"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path := filepath.Join(p.dir, "project-loose.key")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// Reading a key another account can also read would silently widen the
	// trust boundary, so this must fail rather than warn.
	_, err := p.Load("project-loose")
	if err == nil {
		t.Fatal("Load accepted a world-readable key file, want an error")
	}
	if errors.Is(err, vault.ErrKeyMissing) {
		t.Fatal("a loose-permission key must not be reported as missing: vault.Open would overwrite it")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error should tell the user how to fix it, got: %v", err)
	}
}

func TestFileProtectorSaveOverwritesExistingKey(t *testing.T) {
	p := newTestFileProtector(t)

	if err := p.Save("project-rot", "Zmlyc3Q"); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := p.Save("project-rot", "c2Vjb25k"); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	got, err := p.Load("project-rot")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != "c2Vjb25k" {
		t.Errorf("Load returned %q after overwrite, want %q", got, "c2Vjb25k")
	}

	// The atomic write must not leave its temporary file behind.
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		t.Fatalf("read key dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".key-") {
			t.Errorf("temporary key file %s was left behind", e.Name())
		}
	}
}

func TestFileProtectorRejectsUnsafeKeyName(t *testing.T) {
	p := newTestFileProtector(t)

	// A name carrying a path separator would escape the owner-only directory.
	if err := p.Save("../escape", "a2V5"); err == nil {
		t.Error("Save accepted a traversing key name, want an error")
	}
	if _, err := p.Load("../escape"); err == nil {
		t.Error("Load accepted a traversing key name, want an error")
	}
}

func TestOpenVaultRejectsUnknownProtector(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(ProtectorEnv, "bogus")

	_, err := OpenVault(Identity{RemoteURL: "https://github.com/acme/app", CanonicalPath: "/tmp/app"})
	if err == nil {
		t.Fatal("OpenVault accepted an unknown protector, want an error")
	}
	if !strings.Contains(err.Error(), ProtectorEnv) {
		t.Errorf("error should name %s, got: %v", ProtectorEnv, err)
	}
}

func TestOpenVaultWithFileProtectorStoresAndReadsValue(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(ProtectorEnv, "file")

	identity := Identity{RemoteURL: "https://github.com/acme/app", CanonicalPath: "/tmp/app"}
	store, err := OpenVault(identity)
	if err != nil {
		t.Fatalf("OpenVault with file protector: %v", err)
	}

	if err := store.Set("dev", "DATABASE_URL", "postgres://localhost/db"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get("dev", "DATABASE_URL")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "postgres://localhost/db" {
		t.Errorf("Get returned %q, want the stored value", got)
	}

	// A second open must reuse the persisted key rather than generating a new
	// one, which would strand every value already written.
	reopened, err := OpenVault(identity)
	if err != nil {
		t.Fatalf("reopen vault: %v", err)
	}
	if got, err = reopened.Get("dev", "DATABASE_URL"); err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got != "postgres://localhost/db" {
		t.Errorf("value did not survive reopen, got %q", got)
	}
}

func TestOpenVaultFileProtectorWritesNoPlaintext(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(ProtectorEnv, "file")

	store, err := OpenVault(Identity{RemoteURL: "https://github.com/acme/app", CanonicalPath: "/tmp/app"})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	const secret = "sk-live-do-not-write-this-in-the-clear"
	if err := store.Set("dev", "STRIPE_SECRET_KEY", secret); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Neither the vault document nor the wrapped key may contain the value or
	// the key name in the clear.
	err = filepath.Walk(filepath.Join(home, ".ironrun"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), secret) {
			t.Errorf("%s contains the secret value in plaintext", path)
		}
		if strings.Contains(string(data), "STRIPE_SECRET_KEY") {
			t.Errorf("%s contains the secret name in plaintext", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk ironrun home: %v", err)
	}
}
