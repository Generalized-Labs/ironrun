// Package githooks installs per-repo git hooks that block commits and pushes
// containing managed secret values.
//
// Two layers, per the leak-prevention spec:
//  1. Scanner layer: gitleaks (or Betterleaks) on the staged diff, if present
//     on PATH. Skipped with a loud warning when absent.
//  2. ironrun exact-value layer: the staged diff (pre-commit) or the pushed
//     commit range (pre-push) is piped through `ironrun git scan-diff`,
//     which matches every managed vault value plus its encoded variants.
//     Zero false positives: ironrun knows the exact values.
//
// The hooks are thin shell wrappers; all matching logic lives in the
// `ironrun git check-staged|check-push|scan-diff` subcommands so it can be
// tested and updated without reinstalling hooks.
package githooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Marker identifies hooks and file sections managed by ironrun.
const Marker = "# managed by ironrun git install-hooks"

// PreCommitScript returns the pre-commit hook: blocks the commit when either
// layer finds a secret in the staged diff.
//
// Fail-closed: when the ironrun binary is missing the hook BLOCKS the commit
// instead of silently skipping the exact-value check. A hook that promises to
// block secrets must not pass when it cannot check.
func PreCommitScript() string {
	return `#!/bin/sh
` + Marker + ` — do not edit; re-run ` + "`ironrun git install-hooks`" + ` to regenerate.
# Layer 1: gitleaks / Betterleaks on the staged diff, when available.
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks protect --staged --redact --verbose || exit 1
elif command -v betterleaks >/dev/null 2>&1; then
    betterleaks protect --staged --redact || exit 1
else
    echo "ironrun hook: no gitleaks/Betterleaks on PATH — scanner layer skipped" >&2
fi
# Layer 2: ironrun exact-value check of the staged diff.
IRONRUN_BIN="${IRONRUN_BIN:-$(command -v ironrun || true)}"
if [ -z "$IRONRUN_BIN" ]; then
    echo "ironrun hook: BLOCKED — ironrun not on PATH, exact-value check cannot run." >&2
    echo "Reinstall ironrun, or remove these hooks with: ironrun git uninstall-hooks" >&2
    exit 1
fi
"$IRONRUN_BIN" git check-staged || exit 1
exit 0
`
}

// PrePushScript returns the pre-push hook: blocks the push when the pushed
// commit range contains a managed secret. stdin lines are
// "<local ref> <local sha> <remote ref> <remote sha>".
//
// Fail-closed like the pre-commit hook: a missing ironrun binary BLOCKS the
// push (this hook has no scanner layer at all, so skipping would leave the
// push completely unguarded).
func PrePushScript() string {
	return `#!/bin/sh
` + Marker + ` — do not edit; re-run ` + "`ironrun git install-hooks`" + ` to regenerate.
IRONRUN_BIN="${IRONRUN_BIN:-$(command -v ironrun || true)}"
if [ -z "$IRONRUN_BIN" ]; then
    echo "ironrun hook: BLOCKED — ironrun not on PATH, push cannot be scanned." >&2
    echo "Reinstall ironrun, or remove these hooks with: ironrun git uninstall-hooks" >&2
    exit 1
fi
# Pass the push plan to ironrun; it computes the commit ranges and scans them.
"$IRONRUN_BIN" git check-push || exit 1
exit 0
`
}

// gitignoreEntries are appended to the repo's .gitignore by Install.
// .ironrun/ holds environments.json, access state, pending approvals and
// migrations — repo-local but never committable.
var gitignoreEntries = []string{
	".ironrun/",
}

// InstallResult describes what install-hooks changed.
type InstallResult struct {
	HooksDir      string
	PreCommit     string // path written
	PrePush       string // path written
	HooksRewrote  int
	GitignoreAdds []string
}

// Install writes the pre-commit and pre-push hooks into the git hooks dir
// of the repo at repoRoot and ensures .gitignore coverage. It is idempotent:
// re-running rewrites ironrun-managed hooks and never duplicates .gitignore
// entries. A pre-existing hook NOT managed by ironrun is left alone and
// reported as an error unless force is true.
func Install(repoRoot string, force bool) (*InstallResult, error) {
	hooksDir, err := hooksDirFor(repoRoot)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return nil, fmt.Errorf("create hooks dir: %w", err)
	}
	res := &InstallResult{HooksDir: hooksDir}
	for name, script := range map[string]string{
		"pre-commit": PreCommitScript(),
		"pre-push":   PrePushScript(),
	} {
		path := filepath.Join(hooksDir, name)
		if data, err := os.ReadFile(path); err == nil {
			if !strings.Contains(string(data), Marker) && !force {
				return nil, fmt.Errorf("%s exists and is not ironrun-managed; move it aside or re-run with --force", path)
			}
			if string(data) == script {
				continue // already installed, byte-identical
			}
		}
		if err := writeExecutable(path, script); err != nil {
			return nil, err
		}
		res.HooksRewrote++
		switch name {
		case "pre-commit":
			res.PreCommit = path
		case "pre-push":
			res.PrePush = path
		}
	}
	added, err := ensureGitignore(repoRoot)
	if err != nil {
		return nil, err
	}
	res.GitignoreAdds = added
	return res, nil
}

// EnsureGitignore appends the ironrun entries to the repo .gitignore,
// creating it if needed. Idempotent: existing entries are never duplicated.
func EnsureGitignore(repoRoot string) ([]string, error) { return ensureGitignore(repoRoot) }

// UninstallResult describes what uninstall-hooks removed.
type UninstallResult struct {
	HooksRemoved     []string
	GitignoreCleaned bool
}

// Uninstall removes the ironrun-managed hooks and the managed .gitignore
// section from the repo at repoRoot. Hooks that do not carry the ironrun
// marker are left alone. Idempotent: re-running is a no-op.
func Uninstall(repoRoot string) (*UninstallResult, error) {
	hooksDir, err := hooksDirFor(repoRoot)
	if err != nil {
		return nil, err
	}
	res := &UninstallResult{}
	for _, name := range []string{"pre-commit", "pre-push"} {
		path := filepath.Join(hooksDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue // not present: nothing to do
		}
		if !strings.Contains(string(data), Marker) {
			continue // foreign hook: leave alone
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove %s: %w", path, err)
		}
		res.HooksRemoved = append(res.HooksRemoved, path)
	}
	cleaned, err := removeGitignoreSection(repoRoot)
	if err != nil {
		return nil, err
	}
	res.GitignoreCleaned = cleaned
	return res, nil
}

// removeGitignoreSection drops the marker line written by ensureGitignore
// plus the managed entries that follow it. Reports whether anything changed.
func removeGitignoreSection(repoRoot string) (bool, error) {
	path := filepath.Join(repoRoot, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil // no .gitignore: nothing to do
	}
	managed := map[string]bool{}
	for _, e := range gitignoreEntries {
		managed[e] = true
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	removed := false
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == Marker {
			removed = true
			for i+1 < len(lines) && managed[strings.TrimSpace(lines[i+1])] {
				i++
			}
			continue
		}
		out = append(out, lines[i])
	}
	if !removed {
		return false, nil
	}
	if err := atomicWriteFile(path, []byte(strings.Join(out, "\n")), 0o644); err != nil {
		return false, fmt.Errorf("write .gitignore: %w", err)
	}
	return true, nil
}

// atomicWriteFile writes path via tmp + rename so a crash can never leave a
// truncated file behind.
func atomicWriteFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ironrun-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck
	if _, err := tmp.Write(content); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func ensureGitignore(repoRoot string) ([]string, error) {
	path := filepath.Join(repoRoot, ".gitignore")
	var existing []string
	var raw string
	if data, err := os.ReadFile(path); err == nil {
		raw = string(data)
		existing = strings.Split(raw, "\n")
	}
	have := map[string]bool{}
	for _, l := range existing {
		have[strings.TrimSpace(l)] = true
	}
	var added []string
	var missing []string
	for _, e := range gitignoreEntries {
		if !have[e] {
			missing = append(missing, e)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	var sb strings.Builder
	sb.WriteString(raw)
	if raw != "" && !strings.HasSuffix(raw, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString(Marker + "\n")
	for _, e := range missing {
		sb.WriteString(e + "\n")
		added = append(added, e)
	}
	if err := atomicWriteFile(path, []byte(sb.String()), 0o644); err != nil {
		return nil, fmt.Errorf("write .gitignore: %w", err)
	}
	return added, nil
}

// hooksDirFor asks git which directory it runs hooks from for repoRoot.
// `--git-path hooks` honors core.hooksPath (husky and friends) and resolves a
// linked worktree to the common dir; <gitdir>/hooks is wrong in both cases,
// and hooks written there silently never run.
func hooksDirFor(repoRoot string) (string, error) {
	out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", fmt.Errorf("%s is not a git repository", repoRoot)
	}
	dir := strings.TrimRight(string(out), "\n")
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(repoRoot, dir) // relative to the -C directory
	}
	return dir, nil
}

// writeExecutable writes path atomically (tmp + rename) with 0755.
func writeExecutable(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ironrun-hook-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
