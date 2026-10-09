// Package audit writes a tamper-evident, append-only record of every sealed
// command execution. Each entry is a single JSON line; entries are linked by a
// SHA-256 hash chain (each record stores the hash of the previous one), so any
// retroactive edit to an entry breaks the chain and is detectable by Verify.
//
// Open verifies the existing chain before returning: a tampered log fails
// loudly at open time instead of being silently appended to.
//
// The log records command metadata only — command id, argv, the *names* of the
// secrets injected, redaction/entropy counts, exit code, and timing. It never
// records secret values: Append scrubs every ScrubValues entry (plus cheap
// encoded variants, mirroring the runner's redaction registration) out of
// Argv before the record is hashed and written.
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/generalized-labs/ironrun/internal/redact"
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
	SeccompRequested bool `json:"seccomp_requested"`
	// SeccompInstalled records whether the seccomp filter was actually
	// installed for this run, read from the runner immediately after the run
	// (internal/audit cannot import internal/runner — import cycle — so the
	// runner populates this field at the audit call site).
	//
	// omitempty keeps old (pre-0.6) log records verifiable: with the zero
	// value the field serializes to nothing, so recomputed hashes of old
	// records still match.
	SeccompInstalled bool `json:"seccomp_installed,omitempty"`
	// SeccompDetail is the human-readable seccomp outcome, e.g. why the
	// filter was not installed. Empty when not applicable.
	SeccompDetail string `json:"seccomp_detail,omitempty"`
	NoNetwork     bool   `json:"no_network"`
	PrevHash      string `json:"prev_hash"`
	Hash          string `json:"hash"`
	// ScrubValues carries secret values that must never appear in the stored
	// record. It is never serialized (json:"-"): Append strips every
	// occurrence of each value — plus cheap encoded variants derived via
	// redact.Encodings, mirroring the runner's redaction registration — from
	// Argv before the entry is hashed and written.
	ScrubValues []string `json:"-"`
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
//
// Verify-on-open: the existing chain is replayed before the logger is
// returned, and a tampered log fails loudly here instead of being silently
// appended to. Verification replays the whole file, so Open is O(log size);
// audit records are small and Open runs once per process, which is an
// acceptable cost for the integrity guarantee.
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
	if broken, verr := Verify(path); verr != nil {
		f.Close()
		return nil, fmt.Errorf("audit: cannot verify existing log %s: %w", path, verr)
	} else if broken != -1 {
		f.Close()
		return nil, fmt.Errorf("audit: TAMPER DETECTED: hash chain of %s is broken at record %d — refusing to open. Inspect it with `ironrun audit verify --log %s`; to recover, move it aside as evidence (mv %s %s.tampered) and the next run starts a new chain", path, broken, path, path, path)
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

	// Scrub secret values out of argv BEFORE the entry is hashed and written:
	// policy argv can legitimately embed a secret (e.g. a --token= flag), and
	// the audit log must record names only, never values.
	if len(e.ScrubValues) > 0 {
		e.Argv = scrubSecrets(e.Argv, e.ScrubValues)
		e.ScrubValues = nil
	}

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

const (
	// scrubPlaceholder matches the redactor's placeholder (internal/redact),
	// so scrubbed argv reads the same as redacted output.
	scrubPlaceholder = "[REDACTED]"
	// Values shorter than this are not scrubbed: exact-matching a 1-3 byte
	// token would mangle ordinary argv while protecting nothing real. This
	// mirrors the runner's minRedactableSecretLen.
	minScrubSecretLen = 4
	// Encoded variants (base64/hex/url) are only derived for values at least
	// this long, mirroring the runner's minEncodableSecretLen, so the
	// derivations stay specific enough not to over-scrub ordinary argv.
	minEncodableSecretLen = 8
)

// scrubSecrets returns argv with every occurrence of each secret value — plus
// its cheap encoded variants from redact.Encodings — replaced by
// scrubPlaceholder. It allocates a new slice; the caller's argv is untouched.
func scrubSecrets(argv []string, values []string) []string {
	needles := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) < minScrubSecretLen {
			continue
		}
		needles = append(needles, v)
		if len(v) >= minEncodableSecretLen {
			needles = append(needles, redact.Encodings(v, minEncodableSecretLen)...)
		}
	}
	if len(needles) == 0 {
		return argv
	}
	// Dedupe and replace longest needles first so a more specific variant
	// wins over a shorter overlapping one.
	seen := make(map[string]bool, len(needles))
	uniq := needles[:0]
	for _, n := range needles {
		if !seen[n] {
			seen[n] = true
			uniq = append(uniq, n)
		}
	}
	sort.Slice(uniq, func(i, j int) bool { return len(uniq[i]) > len(uniq[j]) })

	out := make([]string, len(argv))
	for i, arg := range argv {
		for _, n := range uniq {
			if strings.Contains(arg, n) {
				arg = strings.ReplaceAll(arg, n, scrubPlaceholder)
			}
		}
		out[i] = arg
	}
	return out
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
// policy's audit_log field, then a per-user default in the state directory.
// "off" (as the policy field) disables auditing.
//
// The legacy IRONRUN_AUDIT_LOG environment variable is deliberately NOT
// honored. A contained agent inherits the environment, so an env-gated audit
// control is agent-reachable: IRONRUN_AUDIT_LOG=off would silently disable
// the audit trail — the one record that must survive agent interference —
// and any other value would redirect it somewhere the operator never looks.
// Configure the path via the audit_log: policy field instead. A loud warning
// is emitted when the env var is set so operators learn the new mechanism
// instead of silently losing their setting.
func ResolvePath(policyField string) string {
	if v, ok := os.LookupEnv("IRONRUN_AUDIT_LOG"); ok && v != "" {
		fmt.Fprintf(os.Stderr, "[ironrun] SECURITY WARNING: IRONRUN_AUDIT_LOG is set but no longer honored (the audit path is agent-reachable via the environment); set the audit_log: field in your policy file instead\n")
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
