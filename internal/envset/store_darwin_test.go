//go:build darwin

package envset

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSecurity replaces the `security` CLI on PATH with a script that keeps
// items as files, logs every argv, and never touches a real keychain. It
// accepts writes both as argv and as a `security -i` stdin line. With
// silent=true, writes exit 0 without storing anything, which is what
// `security -i` does on a locked keychain.
func fakeSecurity(t *testing.T, silent bool) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
echo "$*" >> "$FAKE_DIR/argv"
item() { printf '%s' "$1|$2" | shasum | cut -c1-40; }
if [ "$1" = "-i" ]; then
  read -r _ _ _ s _ a _ x
elif [ "$1" = "add-generic-password" ]; then
  s=$4 a=$6 x=$8
fi
if [ -n "$x" ]; then
  [ -n "$FAKE_SILENT" ] && exit 0
  printf '%s' "$x" | xxd -r -p > "$FAKE_DIR/$(item "$s" "$a")"
  exit 0
fi
if [ "$1" = "find-generic-password" ]; then
  f="$FAKE_DIR/$(item "$3" "$5")"
  [ -f "$f" ] || exit 44
  cat "$f"; echo
  exit 0
fi
exit 1
`
	if err := os.WriteFile(filepath.Join(dir, "security"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DIR", dir)
	if silent {
		t.Setenv("FAKE_SILENT", "1")
	}
	return dir
}

func TestKeychainWriteKeepsCredentialOutOfArgv(t *testing.T) {
	dir := fakeSecurity(t, false)
	const rootKey = "v2L3vZyDKsiDTRFf9CxY6QvgUwQLFqDYRRzQxPVbVrw"
	if err := (nativeStore{}).Set("vault-keys", "project-0123", rootKey); err != nil {
		t.Fatal(err)
	}
	if got, err := (nativeStore{}).Get("vault-keys", "project-0123"); err != nil || got != rootKey {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	argv, err := os.ReadFile(filepath.Join(dir, "argv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{rootKey, hex.EncodeToString([]byte(rootKey))} {
		if strings.Contains(string(argv), form) {
			t.Fatalf("credential appeared in security argv:\n%s", argv)
		}
	}
}

func TestKeychainWriteFailsWhenInteractiveModeSilentlyStoresNothing(t *testing.T) {
	fakeSecurity(t, true)
	if err := (nativeStore{}).Set("vault-keys", "project-0123", "secret"); err == nil {
		t.Fatal("unverified keychain write reported success")
	}
}
