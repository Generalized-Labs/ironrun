package scrub

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// StoreRoot is one agent-CLI session store: a name plus the candidate
// directories that hold its persisted transcripts. Only files under these
// roots are ever touched — agent-scrub never walks anywhere else.
type StoreRoot struct {
	Name string
	Dirs []string
}

// KnownRoots returns the six supported agent-CLI session stores. Directory
// overrides from the environment are honored where the vendor documents one.
func KnownRoots() []StoreRoot {
	home, _ := os.UserHomeDir()
	claudeDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if claudeDir == "" {
		claudeDir = filepath.Join(home, ".claude")
	}
	codexDir := os.Getenv("CODEX_HOME")
	if codexDir == "" {
		codexDir = filepath.Join(home, ".codex")
	}
	copilotDir := os.Getenv("COPILOT_HOME")
	if copilotDir == "" {
		copilotDir = filepath.Join(home, ".copilot")
	}
	geminiDir := os.Getenv("GEMINI_HOME")
	if geminiDir == "" {
		geminiDir = filepath.Join(home, ".gemini")
	}
	return []StoreRoot{
		{Name: "claude", Dirs: []string{filepath.Join(claudeDir, "projects"), claudeDir}},
		{Name: "codex", Dirs: []string{filepath.Join(codexDir, "sessions"), filepath.Join(codexDir, "archived_sessions")}},
		{Name: "copilot", Dirs: []string{filepath.Join(copilotDir, "session-state"), filepath.Join(copilotDir, "history-session-state")}},
		{Name: "gemini", Dirs: []string{filepath.Join(geminiDir, "tmp")}},
		{Name: "cursor", Dirs: []string{filepath.Join(home, ".cursor", "projects"), filepath.Join(home, ".cursor", "plans")}},
		{Name: "windsurf", Dirs: []string{filepath.Join(home, ".windsurf"), filepath.Join(home, ".codeium", "windsurf")}},
	}
}

// MaxFileSize caps how large a transcript file may be to be scrubbed.
// Larger files are reported as skipped, never truncated or half-written.
const MaxFileSize = 128 << 20 // 128 MiB

// textExts are scrubbed as plain text. Extensionless files (e.g. Gemini's
// shell_history) are included; known binary stores are excluded below.
var textExts = map[string]bool{
	".jsonl": true, ".json": true, ".txt": true, ".log": true, ".md": true,
}

// binaryExts are never touched: SQLite stores (Cursor/Windsurf vscdb,
// Copilot session-store.db, Codex state sqlite) and Windsurf's opaque
// .pb bundles cannot be rewritten safely without their native formats.
// They are reported as skipped so the user knows the residual surface.
var binaryExts = map[string]bool{
	".vscdb": true, ".db": true, ".sqlite": true, ".sqlite3": true,
	".pb": true, ".wal": true, ".shm": true, ".bin": true,
}

// FileResult describes what happened to one transcript file.
type FileResult struct {
	Store      string
	Path       string
	Matches    int  // values/variants found
	Rewritten  bool // file was rewritten (apply mode, matches > 0)
	Skipped    bool
	SkipReason string
}

// ScanResult aggregates one scrub run.
type ScanResult struct {
	Files    []FileResult
	Scanned  int // files examined
	Matched  int // files containing at least one match
	Rewrote  int // files rewritten
	SkippedN int // files skipped (binary/too large/etc.)
}

// Scrub walks the given store roots, redacts known values from transcript
// files, and — only when apply is true — rewrites files atomically
// (temp file + rename, original mode preserved). With apply=false it is a
// pure dry-run: nothing on disk changes. It is idempotent: files whose
// values are already replaced report zero matches and are never rewritten.
func Scrub(m *Matcher, roots []StoreRoot, apply bool) (*ScanResult, error) {
	res := &ScanResult{}
	seen := map[string]bool{} // dirs may overlap between entries
	seenFile := map[string]bool{}
	for _, r := range roots {
		for _, dir := range r.Dirs {
			abs, err := filepath.Abs(dir)
			if err != nil {
				continue
			}
			if seen[abs] {
				continue
			}
			seen[abs] = true
			info, err := os.Stat(abs)
			if err != nil || !info.IsDir() {
				continue
			}
			if err := walkDir(m, r.Name, abs, apply, seenFile, res); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

func walkDir(m *Matcher, store, dir string, apply bool, seenFile map[string]bool, res *ScanResult) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entry: record it as skipped so a scan can never
			// report "clean" while directories were silently unread.
			res.SkippedN++
			res.Files = append(res.Files, FileResult{Store: store, Path: path, Skipped: true, SkipReason: "unreadable: " + err.Error()})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if seenFile[path] {
			return nil // overlapping roots (e.g. ~/.claude and ~/.claude/projects)
		}
		seenFile[path] = true
		if d.Type()&fs.ModeSymlink != 0 {
			res.SkippedN++
			res.Files = append(res.Files, FileResult{Store: store, Path: path, Skipped: true, SkipReason: "symlink (never followed)"})
			return nil
		}
		if !scrubbable(path) {
			res.SkippedN++
			res.Files = append(res.Files, FileResult{Store: store, Path: path, Skipped: true, SkipReason: skipReason(path)})
			return nil
		}
		info, err := d.Info()
		if err != nil {
			res.SkippedN++
			res.Files = append(res.Files, FileResult{Store: store, Path: path, Skipped: true, SkipReason: "cannot stat: " + err.Error()})
			return nil
		}
		if info.Size() > MaxFileSize {
			res.SkippedN++
			res.Files = append(res.Files, FileResult{Store: store, Path: path, Skipped: true, SkipReason: fmt.Sprintf("exceeds %d MiB cap", MaxFileSize>>20)})
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			res.SkippedN++
			res.Files = append(res.Files, FileResult{Store: store, Path: path, Skipped: true, SkipReason: "cannot read: " + err.Error()})
			return nil
		}
		if isBinary(data) {
			res.SkippedN++
			res.Files = append(res.Files, FileResult{Store: store, Path: path, Skipped: true, SkipReason: "binary content (not a text transcript)"})
			return nil
		}
		res.Scanned++
		redacted, n := m.Redact(string(data))
		fr := FileResult{Store: store, Path: path, Matches: n}
		if n == 0 {
			res.Files = append(res.Files, fr) // clean or already scrubbed
			return nil
		}
		res.Matched++
		if !apply {
			res.Files = append(res.Files, fr)
			return nil
		}
		if err := atomicReplace(path, []byte(redacted), info.Mode()); err != nil {
			return fmt.Errorf("rewrite %s: %w", path, err)
		}
		fr.Rewritten = true
		res.Rewrote++
		res.Files = append(res.Files, fr)
		return nil
	})
}

// scrubbable reports whether path is a candidate transcript file.
// Anything outside the known text extensions or the binary exclusion list
// is rejected: when in doubt we leave the file alone.
func scrubbable(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if binaryExts[ext] {
		return false
	}
	if ext == "" {
		return true // e.g. Gemini's shell_history
	}
	return textExts[ext]
}

func skipReason(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if binaryExts[ext] {
		return "binary store (" + ext + " — SQLite/opaque, cannot scrub safely)"
	}
	return "unsupported extension (" + ext + ")"
}

// isBinary sniffs the head of the file for NUL bytes.
func isBinary(data []byte) bool {
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	for _, c := range head {
		if c == 0 {
			return true
		}
	}
	return false
}

// atomicReplace writes data to path via a temp file in the same directory
// followed by rename, preserving the original file mode.
func atomicReplace(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ironrun-scrub-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
