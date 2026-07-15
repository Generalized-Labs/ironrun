// Package audit writes a tamper-evident, append-only record of every sealed
// command execution. Each entry is a single JSON line; entries are linked by a
// SHA-256 hash chain (each record stores the hash of the previous one), so any
// retroactive edit to an entry breaks the chain and is detectable by Verify.
//
// The log records command metadata only — command id, argv, the *names* of the
// secrets injected, redaction/entropy counts, exit code, and timing. It never
// records secret values.
//
// The chain is tamper-*evident*, not tamper-*proof*: an attacker who can rewrite
// the whole file can recompute every hash. It exists to detect after-the-fact
// edits, not to prevent a wholesale rewrite.
package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	schemaVersion = 1
	// genesisHash is the prev_hash of the first record in a chain.
	genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Entry is one audit record. Field order is fixed so the JSON encoding (and
// therefore the hash) is deterministic. No map fields — maps would serialize
// non-deterministically and break the chain.
type Entry struct {
	Timestamp       time.Time   `json:"ts"`
	Schema          int         `json:"schema"`
	SessionID       string      `json:"session_id"`
	Cwd             string      `json:"cwd"`
	CommandID       string      `json:"command_id"`
	Argv            []string    `json:"argv"`         // policy argv — never secret values
	SecretNames     []string    `json:"secret_names"` // env var names only, sorted
	SecretUses      []SecretUse `json:"secret_uses,omitempty"`
	CleanupResult   string      `json:"cleanup_result,omitempty"`
	RedactionCount  int         `json:"redaction_count"`
	EntropyWarnings int         `json:"entropy_warnings"`
	ExitCode        int         `json:"exit_code"`
	DurationMs      int64       `json:"duration_ms"`
	Truncated       bool        `json:"truncated"`
	KillReason      string      `json:"kill_reason"` // "", "timeout", "cancelled"
	// SeccompRequested records whether the parent asked for a seccomp filter.
	// Because seccomp fails open, this is "requested", not a guarantee it was
	// installed (an unsupported kernel logs a warning and runs without it).
	SeccompRequested bool   `json:"seccomp_requested"`
	NoNetwork        bool   `json:"no_network"`
	PrevHash         string `json:"prev_hash"`
	Hash             string `json:"hash"`
}

// SecretUse is safe execution metadata. It never contains a value or a
// materialized path.
type SecretUse struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

// Logger appends entries to a JSONL file, maintaining the hash chain. It is
// safe for concurrent use in-process (mutex) and across processes (flock).
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// Open opens (creating if needed) the audit log at path. A path of "" means
// auditing is disabled and Open returns (nil, nil); the returned *Logger's
// methods are all nil-safe no-ops, so callers need not special-case it.
func Open(path string) (*Logger, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	// O_RDWR (not O_WRONLY) so we can read back the last line for the chain.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Logger{f: f}, nil
}

// Append links e to the current tail of the log and writes it. It reads the
// last record's hash under an exclusive file lock, so the chain stays correct
// even when multiple processes append concurrently.
func (l *Logger) Append(e Entry) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := lockFile(l.f); err != nil {
		return err
	}
	defer unlockFile(l.f)

	prev, err := lastHash(l.f)
	if err != nil {
		return err
	}
	e.Schema = schemaVersion
	e.PrevHash = prev
	e.Hash = computeHash(e)

	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return err
	}
	return l.f.Sync()
}

// Close closes the underlying file. Nil-safe.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	return l.f.Close()
}

// Verify replays the log and checks the hash chain. It returns the 1-based line
// number of the first broken record, or -1 if the chain is intact.
func Verify(path string) (brokenLine int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return -1, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	prev := genesisHash
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			return line, nil
		}
		if e.PrevHash != prev || computeHash(e) != e.Hash {
			return line, nil
		}
		prev = e.Hash
	}
	if err := sc.Err(); err != nil {
		return -1, err
	}
	return -1, nil
}

// computeHash returns the SHA-256 (hex) of the entry with its Hash field zeroed.
// PrevHash IS included in the digest, so tampering with the chain link is caught.
func computeHash(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// lastHash returns the Hash of the final record in f, or genesisHash if empty.
// It reads only the tail of the file (records are small), so Append stays cheap.
func lastHash(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := info.Size()
	if size == 0 {
		return genesisHash, nil
	}
	const window = 64 * 1024
	start := size - window
	if start < 0 {
		start = 0
	}
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return "", err
	}
	trimmed := bytes.TrimRight(buf, "\n")
	if idx := bytes.LastIndexByte(trimmed, '\n'); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	var e Entry
	if err := json.Unmarshal(trimmed, &e); err != nil {
		return "", fmt.Errorf("audit: unreadable last record: %w", err)
	}
	return e.Hash, nil
}

// NewSessionID returns a random hex identifier for correlating entries.
func NewSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// ResolvePath determines the audit log path from, in precedence order: the
// IRONRUN_AUDIT_LOG env var, the policy's audit_log field, then a per-user
// default in the state directory. "off" (or empty env) disables auditing.
func ResolvePath(policyField string) string {
	if v, ok := os.LookupEnv("IRONRUN_AUDIT_LOG"); ok {
		if v == "" || v == "off" {
			return ""
		}
		return expandHome(v)
	}
	if policyField != "" {
		if policyField == "off" {
			return ""
		}
		return expandHome(policyField)
	}
	return defaultPath()
}

// defaultPath returns the per-user default log location, or "" if no safe
// location can be determined (in which case auditing stays off rather than
// guessing).
func defaultPath() string {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "ironrun", "audit.log")
	}
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("LocalAppData"); dir != "" {
			return filepath.Join(dir, "ironrun", "audit.log")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "state", "ironrun", "audit.log")
}

func expandHome(p string) string {
	if p == "~" || (len(p) >= 2 && p[:2] == "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
