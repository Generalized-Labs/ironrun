package shellguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/generalized-labs/ironrun/internal/scrub"
)

// HistoryFile is one shell history file to purge.
type HistoryFile struct {
	Shell string // bash, zsh, fish
	Path  string
}

// HistoryFiles returns the history files for the current user's shells.
// When the process runs inside a shell with HISTFILE set, that file is used
// for that shell; otherwise the conventional default is used.
func HistoryFiles() []HistoryFile {
	home, _ := os.UserHomeDir()
	var out []HistoryFile
	seen := map[string]bool{}
	add := func(shell, path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		out = append(out, HistoryFile{Shell: shell, Path: path})
	}
	histfile := os.Getenv("HISTFILE")
	if os.Getenv("BASH_VERSION") != "" && histfile != "" {
		add("bash", histfile)
	} else {
		add("bash", filepath.Join(home, ".bash_history"))
	}
	if os.Getenv("ZSH_VERSION") != "" && histfile != "" {
		add("zsh", histfile)
	} else {
		add("zsh", filepath.Join(home, ".zsh_history"))
	}
	xdg := os.Getenv("XDG_DATA_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".local", "share")
	}
	add("fish", filepath.Join(xdg, "fish", "fish_history"))
	return out
}

// PurgeFileResult describes what happened to one history file.
type PurgeFileResult struct {
	Shell        string
	Path         string
	MatchedLines int
	Backup       string // backup path written (apply mode only)
	Rewritten    bool
	Missing      bool // file did not exist: nothing to do
}

// PurgeResult aggregates one purge run.
type PurgeResult struct {
	Files   []PurgeFileResult
	Matched int // total matched lines
	Rewrote int // files rewritten
	DryRun  bool
}

// Purge drops every history line containing a managed value (or an encoded
// variant). With apply=false it is a dry-run: files are only counted. With
// apply=true each touched file is first backed up to <path>.ironrun.bak
// (an existing backup is never overwritten) and then rewritten atomically
// (temp file + rename). Re-running is a no-op: no matches, no rewrites.
func Purge(m *scrub.Matcher, files []HistoryFile, apply bool) (*PurgeResult, error) {
	res := &PurgeResult{DryRun: !apply}
	for _, f := range files {
		fr, err := purgeFile(f, m, apply)
		if err != nil {
			return res, err
		}
		res.Files = append(res.Files, fr)
		res.Matched += fr.MatchedLines
		if fr.Rewritten {
			res.Rewrote++
		}
	}
	return res, nil
}

func purgeFile(f HistoryFile, m *scrub.Matcher, apply bool) (PurgeFileResult, error) {
	fr := PurgeFileResult{Shell: f.Shell, Path: f.Path}
	data, err := os.ReadFile(f.Path)
	if os.IsNotExist(err) {
		fr.Missing = true
		return fr, nil
	}
	if err != nil {
		return fr, fmt.Errorf("read %s: %w", f.Path, err)
	}
	lines := strings.Split(string(data), "\n")
	// Trailing newline produces a final empty element; keep it for rewrite.
	var kept []string
	dropped := 0
	for i := 0; i < len(lines); i++ {
		if m.Contains(lines[i]) {
			dropped++
			// fish_history pairs `- cmd:` with a following `  when:` line;
			// drop the orphaned timestamp with its command.
			if f.Shell == "fish" && i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  when:") {
				i++
			}
			continue
		}
		kept = append(kept, lines[i])
	}
	fr.MatchedLines = dropped
	if dropped == 0 || !apply {
		return fr, nil
	}
	backup := f.Path + ".ironrun.bak"
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		if err := copyFile(f.Path, backup); err != nil {
			return fr, fmt.Errorf("backup %s: %w", f.Path, err)
		}
		fr.Backup = backup
	} else {
		fr.Backup = backup + " (already existed; kept)"
	}
	if err := atomicWrite(f.Path, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		return fr, fmt.Errorf("rewrite %s: %w", f.Path, err)
	}
	fr.Rewritten = true
	return fr, nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// atomicWrite replaces path via temp file + rename.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ironrun-history-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
