// Package audit writes a local, append-only JSONL trail of sealed command runs.
//
// The trail is deliberately SECRET-FREE: it records metadata and counts only —
// never secret values, never resolved environment, never the raw argv (only a
// short hash of it). It exists so an operator can answer "what did the agent run
// through ironrun, and did the seal fire?" without itself becoming a leak.
//
// Location: $IRONRUN_AUDIT_PATH, else ~/.ironrun/audit.jsonl, else
// $GITHUB_WORKSPACE/.ironrun/audit.jsonl. Disable with IRONRUN_AUDIT=off.
// Logging is best-effort: a failure to write never breaks a run.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Record is one sealed-run audit line. It must NEVER contain secret values, the
// resolved environment, or the raw argv.
type Record struct {
	Timestamp  string `json:"ts"`    // RFC3339 UTC
	Event      string `json:"event"` // e.g. "run_sealed"
	CommandID  string `json:"command_id"`
	ArgvHash   string `json:"argv_hash"` // sha256(argv joined by NUL), first 16 hex
	Provider   string `json:"provider,omitempty"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	BytesOut   int64  `json:"bytes_out"`
	Redactions int    `json:"redactions"`
	Truncated  bool   `json:"truncated"`
	NoNetwork  bool   `json:"no_network"`
	Isolation  string `json:"isolation,omitempty"` // "enforced" when no_network sealed the run
	Source     string `json:"source,omitempty"`    // "cli" | "mcp" | "action"
	Version    string `json:"ironrun_version,omitempty"`
}

const defaultMaxBytes = 10 << 20 // 10 MiB

var warnOnce sync.Once

// HashArgv returns a short, stable, non-reversible fingerprint of an argv. We
// log this instead of the raw argv because positional args can carry sensitive
// values (a token, an account id, a path).
func HashArgv(argv []string) string {
	sum := sha256.Sum256([]byte(strings.Join(argv, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

// Path resolves the audit file location, or "" if none is available.
func Path() string {
	if p := os.Getenv("IRONRUN_AUDIT_PATH"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".ironrun", "audit.jsonl")
	}
	if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
		return filepath.Join(ws, ".ironrun", "audit.jsonl")
	}
	return ""
}

// Enabled reports whether audit logging is on (it is unless IRONRUN_AUDIT=off).
func Enabled() bool {
	return strings.ToLower(os.Getenv("IRONRUN_AUDIT")) != "off"
}

// Log appends one record. Best-effort: any error is swallowed (warned once) so
// a broken or read-only audit path can never break a sealed run.
func Log(rec Record) {
	if !Enabled() {
		return
	}
	path := Path()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		warn(err)
		return
	}
	rotate(path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		warn(err)
		return
	}
	defer f.Close()
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
}

// rotate renames the log aside when it grows past the cap (single generation).
func rotate(path string) {
	max := int64(defaultMaxBytes)
	if v := os.Getenv("IRONRUN_AUDIT_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			max = n
		}
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < max {
		return
	}
	_ = os.Rename(path, path+".1")
}

func warn(err error) {
	warnOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "[ironrun] warning: audit log unavailable: %v\n", err)
	})
}
