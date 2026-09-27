package githooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreCommitScriptLayers(t *testing.T) {
	s := PreCommitScript()
	for _, want := range []string{
		"gitleaks", "betterleaks",
		"git check-staged", // ironrun exact-value layer
		"scanner layer skipped",
		Marker,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("pre-commit script missing %q", want)
		}
	}
	if !strings.HasPrefix(s, "#!/bin/sh") {
		t.Fatal("pre-commit script missing shebang")
	}
}

func TestPrePushScriptDelegates(t *testing.T) {
	s := PrePushScript()
	if !strings.Contains(s, "git check-push") {
		t.Fatal("pre-push script does not delegate to `ironrun git check-push`")
	}
	if !strings.Contains(s, Marker) {
		t.Fatal("pre-push script missing marker")
	}
}

func fakeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestInstallIdempotent(t *testing.T) {
	root := fakeRepo(t)
	res, err := Install(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.HooksRewrote != 2 {
		t.Fatalf("expected 2 hooks written, got %d", res.HooksRewrote)
	}
	for _, p := range []string{filepath.Join(root, ".git", "hooks", "pre-commit"), filepath.Join(root, ".git", "hooks", "pre-push")} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o755 {
			t.Fatalf("%s not executable: %v", p, st.Mode())
		}
		data, _ := os.ReadFile(p)
		if !strings.Contains(string(data), Marker) {
			t.Fatalf("%s missing marker", p)
		}
	}
	// Re-run: byte-identical hooks are left alone, .gitignore not duplicated.
	res2, err := Install(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if res2.HooksRewrote != 0 {
		t.Fatalf("reinstall rewrote %d hooks, want 0", res2.HooksRewrote)
	}
	gi, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
	if strings.Count(string(gi), ".ironrun/") != 1 {
		t.Fatalf(".gitignore entry duplicated:\n%s", gi)
	}
	if strings.Count(string(gi), Marker) != 1 {
		t.Fatalf(".gitignore marker duplicated:\n%s", gi)
	}
}

func TestInstallRefusesForeignHook(t *testing.T) {
	root := fakeRepo(t)
	foreign := filepath.Join(root, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\necho foreign\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(root, false); err == nil {
		t.Fatal("expected error on foreign hook without --force")
	}
	if _, err := Install(root, true); err != nil {
		t.Fatalf("force install failed: %v", err)
	}
	data, _ := os.ReadFile(foreign)
	if !strings.Contains(string(data), Marker) {
		t.Fatal("force install did not replace foreign hook")
	}
}

func TestInstallNotARepo(t *testing.T) {
	if _, err := Install(t.TempDir(), false); err == nil {
		t.Fatal("expected error outside a git repo")
	}
}

func TestEnsureGitignoreDedupes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("node_modules/\n.ironrun/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	added, err := EnsureGitignore(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 0 {
		t.Fatalf("expected no additions, got %v", added)
	}
	// Missing trailing newline is normalized, not duplicated.
	root2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(root2, ".gitignore"), []byte("dist/"), 0o644); err != nil {
		t.Fatal(err)
	}
	added, err = EnsureGitignore(root2)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != ".ironrun/" {
		t.Fatalf("expected [.ironrun/], got %v", added)
	}
	gi, _ := os.ReadFile(filepath.Join(root2, ".gitignore"))
	if !strings.Contains(string(gi), "dist/\n"+Marker+"\n.ironrun/\n") {
		t.Fatalf("bad .gitignore layout:\n%s", gi)
	}
}

func TestWorktreeGitFile(t *testing.T) {
	root := t.TempDir()
	realGit := t.TempDir()
	if err := os.MkdirAll(filepath.Join(realGit, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: "+realGit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Install(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.HooksDir != filepath.Join(realGit, "hooks") {
		t.Fatalf("hooks installed to wrong dir: %s", res.HooksDir)
	}
}

func TestScriptsFailClosedWithoutBinary(t *testing.T) {
	for name, s := range map[string]string{"pre-commit": PreCommitScript(), "pre-push": PrePushScript()} {
		// The missing-binary branch must exit nonzero. Find the guard and
		// require an `exit 1` before any later `exit 0`.
		idx := strings.Index(s, `if [ -z "$IRONRUN_BIN" ]`)
		if idx < 0 {
			t.Fatalf("%s: missing-binary guard not found", name)
		}
		rest := s[idx:]
		guardEnd := strings.Index(rest, "fi")
		if guardEnd < 0 {
			t.Fatalf("%s: unterminated missing-binary guard", name)
		}
		guard := rest[:guardEnd]
		if !strings.Contains(guard, "exit 1") {
			t.Fatalf("%s: missing-binary guard does not exit nonzero", name)
		}
		if strings.Contains(guard, "exit 0") {
			t.Fatalf("%s: missing-binary guard can exit 0 (fail-open)", name)
		}
	}
}

func TestUninstall(t *testing.T) {
	root := fakeRepo(t)
	if _, err := Install(root, false); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureGitignore(root); err != nil {
		t.Fatal(err)
	}
	// A foreign hook must survive uninstall.
	foreign := filepath.Join(root, ".git", "hooks", "post-commit")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\necho foreign\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Uninstall(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.HooksRemoved) != 2 {
		t.Fatalf("expected both managed hooks removed, got %v", res.HooksRemoved)
	}
	if data, err := os.ReadFile(foreign); err != nil || !strings.Contains(string(data), "foreign") {
		t.Fatal("foreign hook was touched by uninstall")
	}
	if !res.GitignoreCleaned {
		t.Fatal("expected .gitignore managed section to be cleaned")
	}
	data, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
	if strings.Contains(string(data), Marker) {
		t.Fatal(".gitignore still contains the marker after uninstall")
	}
	// Idempotent: second run removes nothing and errors nothing.
	res2, err := Uninstall(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.HooksRemoved) != 0 || res2.GitignoreCleaned {
		t.Fatalf("uninstall not idempotent: %+v", res2)
	}
}

func TestUninstallLeavesForeignPreCommit(t *testing.T) {
	root := fakeRepo(t)
	foreign := filepath.Join(root, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Uninstall(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.HooksRemoved) != 0 {
		t.Fatalf("uninstall removed a foreign hook: %v", res.HooksRemoved)
	}
	data, err := os.ReadFile(foreign)
	if err != nil || !strings.Contains(string(data), "echo mine") {
		t.Fatal("foreign pre-commit was touched by uninstall")
	}
}
