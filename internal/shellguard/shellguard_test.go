package shellguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/scrub"
)

const canaryH = "sk-canary-history-9f3a1c77" // synthetic test value, not a real secret

func testMatcher() *scrub.Matcher {
	return scrub.NewMatcher([]scrub.Secret{{Alias: "HIST_KEY", Value: canaryH}})
}

func TestSnippetMarkersAndAliases(t *testing.T) {
	for _, s := range []Shell{Bash, Zsh, Fish} {
		snip := Snippet(s, []string{"MY_DEPLOY_TOKEN"})
		if !strings.Contains(snip, BeginMarker) || !strings.Contains(snip, EndMarker) {
			t.Fatalf("shell %d: snippet missing markers", s)
		}
		if !strings.Contains(snip, "MY_DEPLOY_TOKEN") {
			t.Fatalf("shell %d: alias not embedded", s)
		}
		// The guard must warn loudly, never silently strip, and never print values.
		for _, want := range []string{"ironrun", "history", "Ctrl-C"} {
			if !strings.Contains(snip, want) {
				t.Fatalf("shell %d: snippet missing %q", s, want)
			}
		}
		if strings.Contains(strings.ToLower(snip), "silent") && strings.Contains(snip, "strip") {
			t.Fatalf("shell %d: snippet suggests silent stripping", s)
		}
	}
	// Unsafe alias characters are filtered out of the generated patterns.
	snip := Snippet(Bash, []string{"EVIL*NAME", "good_name"})
	if strings.Contains(snip, "EVIL*NAME") {
		t.Fatal("unsafe alias leaked into case pattern")
	}
	if !strings.Contains(snip, "good_name") {
		t.Fatal("safe alias missing from case pattern")
	}
}

func TestSnippetShellSpecifics(t *testing.T) {
	if !strings.Contains(Snippet(Bash, nil), "HISTCONTROL=ignoreboth") {
		t.Fatal("bash snippet missing HISTCONTROL")
	}
	if !strings.Contains(Snippet(Bash, nil), "trap") || !strings.Contains(Snippet(Bash, nil), "DEBUG") {
		t.Fatal("bash snippet missing DEBUG trap")
	}
	if !strings.Contains(Snippet(Zsh, nil), "HIST_IGNORE_SPACE") {
		t.Fatal("zsh snippet missing HIST_IGNORE_SPACE")
	}
	if !strings.Contains(Snippet(Zsh, nil), "preexec") {
		t.Fatal("zsh snippet missing preexec hook")
	}
	if !strings.Contains(Snippet(Fish, nil), "fish_preexec") {
		t.Fatal("fish snippet missing fish_preexec")
	}
}

func TestInstallIdempotent(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".bashrc")
	snip := Snippet(Bash, []string{"A1"})
	wrote, err := Install(rc, snip)
	if err != nil || !wrote {
		t.Fatalf("first install: wrote=%v err=%v", wrote, err)
	}
	wrote, err = Install(rc, snip)
	if err != nil || wrote {
		t.Fatalf("second install: wrote=%v err=%v (want no-op)", wrote, err)
	}
	data, _ := os.ReadFile(rc)
	if strings.Count(string(data), BeginMarker) != 1 {
		t.Fatalf("marker block duplicated:\n%s", data)
	}
}

func TestPurgeDryRunThenApply(t *testing.T) {
	dir := t.TempDir()
	bashHist := filepath.Join(dir, ".bash_history")
	content := "ls -la\nexport HIST_KEY=" + canaryH + "\necho done\n"
	if err := os.WriteFile(bashHist, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []HistoryFile{{Shell: "bash", Path: bashHist}}

	// Dry-run: count, change nothing.
	res, err := Purge(testMatcher(), files, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || res.Rewrote != 0 {
		t.Fatalf("dry-run: matched=%d rewrote=%d", res.Matched, res.Rewrote)
	}
	raw, _ := os.ReadFile(bashHist)
	if string(raw) != content {
		t.Fatal("dry-run modified the file")
	}

	// Apply: rewrite atomically, leaving NO plaintext backup behind.
	res, err = Purge(testMatcher(), files, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || res.Rewrote != 1 {
		t.Fatalf("apply: matched=%d rewrote=%d", res.Matched, res.Rewrote)
	}
	if _, err := os.Stat(bashHist + ".ironrun.bak"); !os.IsNotExist(err) {
		t.Fatalf("purge left a plaintext backup behind (err=%v)", err)
	}
	raw, _ = os.ReadFile(bashHist)
	if strings.Contains(string(raw), canaryH) {
		t.Fatalf("value still in history: %s", raw)
	}
	if !strings.Contains(string(raw), "ls -la") || !strings.Contains(string(raw), "echo done") {
		t.Fatalf("clean lines lost: %s", raw)
	}

	// Idempotent: second apply finds nothing.
	res, err = Purge(testMatcher(), files, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 0 || res.Rewrote != 0 {
		t.Fatalf("not idempotent: matched=%d rewrote=%d", res.Matched, res.Rewrote)
	}
}

// A stale .ironrun.bak left by an older ironrun (which DID keep a plaintext
// backup) must be removed when purge runs, so re-running purge self-heals that
// historical leak.
func TestPurgeRemovesStalePlaintextBackup(t *testing.T) {
	dir := t.TempDir()
	hist := filepath.Join(dir, ".bash_history")
	content := "ls\nexport HIST_KEY=" + canaryH + "\necho ok\n"
	if err := os.WriteFile(hist, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate the old behavior's leftover.
	if err := os.WriteFile(hist+".ironrun.bak", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Purge(testMatcher(), []HistoryFile{{Shell: "bash", Path: hist}}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hist + ".ironrun.bak"); !os.IsNotExist(err) {
		t.Errorf("stale plaintext backup was not removed (err=%v)", err)
	}
}

func TestPurgeFishWhenLine(t *testing.T) {
	dir := t.TempDir()
	fishHist := filepath.Join(dir, "fish_history")
	content := "- cmd: ls\n  when: 1700000000\n- cmd: export FOO=" + canaryH + "\n  when: 1700000001\n- cmd: echo hi\n  when: 1700000002\n"
	if err := os.WriteFile(fishHist, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Purge(testMatcher(), []HistoryFile{{Shell: "fish", Path: fishHist}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 {
		t.Fatalf("expected 1 matched line, got %d", res.Matched)
	}
	raw, _ := os.ReadFile(fishHist)
	if strings.Contains(string(raw), canaryH) || strings.Contains(string(raw), "1700000001") {
		t.Fatalf("fish cmd+when pair not dropped: %s", raw)
	}
	if !strings.Contains(string(raw), "echo hi") {
		t.Fatalf("clean fish lines lost: %s", raw)
	}
}

func TestPurgeMissingFile(t *testing.T) {
	res, err := Purge(testMatcher(), []HistoryFile{{Shell: "zsh", Path: filepath.Join(t.TempDir(), "nope")}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Files[0].Missing {
		t.Fatal("missing file not reported")
	}
}

func TestPurgeEncodedVariant(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".zsh_history")
	// zsh extended history format with a base64-encoded value
	b64 := "c2stY2FuYXJ5LWhpc3RvcnktOWYzYTFjNzc=" // base64(canaryH)
	content := ": 1700000000:0;echo hello\n: 1700000001:0;curl -H \"Authorization: Bearer " + b64 + "\" x\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Purge(testMatcher(), []HistoryFile{{Shell: "zsh", Path: p}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || res.Rewrote != 1 {
		t.Fatalf("encoded variant not caught: matched=%d rewrote=%d", res.Matched, res.Rewrote)
	}
}

func TestZshSnippetValidAndNoCommandSubstitution(t *testing.T) {
	s := Snippet(Zsh, []string{"MY_TOKEN"})
	// The warning message renders `export NAME=<value>` with literal
	// backticks. A double-backslash before a backtick would make zsh see an
	// escaped backslash followed by an ACTIVE backtick (command substitution).
	if strings.Contains(s, "\\\\`") {
		t.Fatal("zsh snippet contains \\\\` — zsh would parse the backtick as command substitution")
	}
	if !strings.Contains(s, "\\`export") {
		t.Fatal("zsh snippet lost the escaped backticks around the export warning")
	}
	if zsh, err := exec.LookPath("zsh"); err == nil {
		f := filepath.Join(t.TempDir(), "snippet.zsh")
		if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(zsh, "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("zsh -n failed: %v\n%s", err, out)
		}
	} else {
		t.Skip("zsh not on PATH; structural check only")
	}
}

func TestFishSnippetBackticksLiteral(t *testing.T) {
	s := Snippet(Fish, []string{"MY_TOKEN"})
	// Fish has no backtick substitution: a backslash before a backtick would
	// print a stray backslash, so the snippet must use bare backticks.
	if strings.Contains(s, "\\`") {
		t.Fatal("fish snippet contains \\` — fish would print a stray backslash")
	}
	if !strings.Contains(s, "`export") {
		t.Fatal("fish snippet lost the backticks around the export warning")
	}
}
