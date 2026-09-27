// Package redact provides streaming secret redaction for subprocess output.
//
// The core primitive is a Writer that wraps an underlying io.Writer and
// replaces any occurrence of registered secret values with "[REDACTED]".
//
// Secrets may be split across Write calls (e.g. a secret like "abc123"
// split as "ab" then "c123"). The scanner approach handles this by processing
// the buffer byte-by-byte: a byte is only emitted once we've confirmed that no
// registered secret starts there (or the secret has been fully matched and
// replaced). We always hold back (maxSpan-1) bytes so a secret spanning two
// Write calls is still detected.
//
// Matching happens in three tiers at each buffer position, in order:
//
//  1. Exact match (longest-first). Secrets are indexed by first byte so only
//     candidates sharing the position's first byte are tried.
//  2. Whitespace/control-tolerant match: a secret whose characters appear in
//     order with whitespace or control bytes (<=0x20, 0x7F) interleaved still
//     matches — this catches the "sk-abc\x1bdef" smuggling class and
//     line-wrapped encodings. The match span is bounded by flexSpanCap so the
//     hold-back stays small.
//  3. Fragment match: for long secrets (>= 24 bytes), every contiguous
//     12-byte window is indexed; a 12+ byte fragment of a secret in the
//     output is extended to the maximal contiguous run of that secret and
//     redacted. This catches truncated or pasted fragments.
package redact

import (
	"io"
	"sort"
	"sync"
)

const placeholder = "[REDACTED]"

const (
	// fragmentLen is the fragment window size: any contiguous run of this
	// many secret bytes in the output triggers fragment redaction.
	fragmentLen = 12
	// fragmentMinSecretLen gates fragment indexing to long secrets only;
	// short secrets are already fully covered by exact matching and their
	// fragments would be false-positive prone.
	fragmentMinSecretLen = 24 // 2 * fragmentLen
	// fragmentMaxSecretLen caps fragment indexing memory: a pathological
	// multi-KB "secret" would otherwise create one map entry per byte.
	fragmentMaxSecretLen = 1024
)

// fragHit records which secret (and window offset within it) a fragment key
// belongs to.
type fragHit struct {
	secret []byte
	off    int
}

// Writer is a streaming redacting writer. It is safe for concurrent use.
type Writer struct {
	mu      sync.Mutex
	out     io.Writer
	secrets [][]byte // sorted longest-first so we greedily match the longest secret
	buf     []byte   // rolling buffer — holds unprocessed bytes
	maxLen  int      // max length of any secret
	maxSpan int      // max flex match span over all secrets; drives hold-back

	byFirst   map[byte][]int                // first byte -> indexes into secrets (longest-first)
	fragments map[[fragmentLen]byte]fragHit // 12-byte windows of long secrets

	written int64 // total bytes written to out
	maxOut  int64 // 0 = unlimited

	redactions int64 // count of secret occurrences replaced with the placeholder
}

// New creates a Writer that redacts all values in secrets before writing to out.
// maxOutputBytes caps total output (0 = unlimited).
func New(out io.Writer, secrets []string, maxOutputBytes int64) *Writer {
	w := &Writer{out: out, maxOut: maxOutputBytes}
	for _, s := range secrets {
		if s == "" {
			continue // ignore empty secrets — they'd match everything
		}
		w.addSecretLocked([]byte(s))
	}
	return w
}

// Write implements io.Writer. It appends data to the rolling buffer,
// then advances the scanner: each byte is emitted only once we know it
// cannot be part of an unprocessed secret.
func (w *Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf = append(w.buf, p...)
	if err := w.scan(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush forces all buffered bytes to be scanned, redacted, and written.
// Must be called after the subprocess exits.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scan(true)
}

func (w *Writer) scan(final bool) error {
	for {
		hold := 0
		if !final && w.maxSpan > 1 {
			hold = w.maxSpan - 1
		}

		if len(w.buf) <= hold {
			break
		}

		safeEnd := 0
		matchedLen := 0

		for safeEnd < len(w.buf)-hold {
			if n := w.matchAt(safeEnd); n > 0 {
				matchedLen = n
				break
			}
			safeEnd++
		}

		if safeEnd > 0 {
			if err := w.emit(w.buf[:safeEnd]); err != nil {
				return err
			}
			w.buf = w.buf[safeEnd:]
		}

		if matchedLen > 0 {
			if err := w.emit([]byte(placeholder)); err != nil {
				return err
			}
			w.redactions++
			w.buf = w.buf[matchedLen:]
		} else {
			break
		}
	}

	if len(w.buf) > 0 && cap(w.buf) > 4096 && len(w.buf) < cap(w.buf)/2 {
		newBuf := make([]byte, len(w.buf))
		copy(newBuf, w.buf)
		w.buf = newBuf
	}

	return nil
}

// matchAt tries to match a secret at w.buf[pos:], returning the number of
// buffer bytes to consume (0 = no match). Tiers: exact, then
// whitespace/control-tolerant, then long-secret fragment.
func (w *Writer) matchAt(pos int) int {
	buf := w.buf[pos:]
	if len(buf) == 0 {
		return 0
	}
	cands := w.byFirst[buf[0]]
	// Tier 1: exact, longest-first.
	for _, i := range cands {
		s := w.secrets[i]
		if len(s) > len(buf) {
			continue
		}
		if hasPrefix(buf, s) {
			return len(s)
		}
	}
	// Tier 2: whitespace/control-tolerant.
	for _, i := range cands {
		s := w.secrets[i]
		if n, ok := matchFlex(buf, s, w.maxSpan); ok && n > 0 {
			return n
		}
	}
	// Tier 3: fragment of a long secret.
	if len(w.fragments) > 0 && len(buf) >= fragmentLen {
		var key [fragmentLen]byte
		copy(key[:], buf[:fragmentLen])
		if fh, ok := w.fragments[key]; ok {
			return extendFragment(buf, fh)
		}
	}
	return 0
}

// extendFragment extends a fragment hit (buf[:fragmentLen] equals
// fh.secret[fh.off:fh.off+fragmentLen]) forward to the maximal contiguous run
// of the secret, returning the bytes to consume.
//
// No backward extension is needed: the scanner reaches the run's first byte
// before any later byte, and everything before the current position has
// already been emitted, so a run necessarily starts at the hit position.
func extendFragment(buf []byte, fh fragHit) int {
	end := fragmentLen
	for end < len(buf) && fh.off+end < len(fh.secret) && buf[end] == fh.secret[fh.off+end] {
		end++
	}
	return end
}

// isFlexGap reports whether b is ignorable between secret characters:
// ASCII whitespace/control bytes and DEL. This is the normalization behind
// tier-2 matching — values split by spaces, newlines, tabs, or smuggled
// control characters still match.
func isFlexGap(b byte) bool {
	return b <= 0x20 || b == 0x7F
}

// flexSpanCap bounds how far a tier-2 match may reach from its start byte.
// The hold-back is derived from the maximum over all secrets, so the cap
// keeps streaming latency bounded while covering realistic smuggling
// (sparse interstitial bytes, openssl-style line wrapping).
func flexSpanCap(secretLen int) int {
	return 2*secretLen + 32
}

// matchFlex reports whether secret matches at the start of buf when
// whitespace/control bytes in either string are ignored, returning the
// number of buf bytes consumed (trailing skipped gaps excluded, so adjacent
// legitimate whitespace is preserved).
func matchFlex(buf, secret []byte, maxSpan int) (int, bool) {
	i, j := 0, 0
	end := 0
	for {
		for j < len(secret) && isFlexGap(secret[j]) {
			j++
		}
		if j == len(secret) {
			return end, true
		}
		for i < len(buf) && isFlexGap(buf[i]) {
			i++
		}
		// The consumed span must stay within maxSpan (the hold-back
		// guarantees maxSpan bytes are visible at scan time); i is the
		// index about to be consumed, so i < maxSpan keeps end <= maxSpan.
		if i >= len(buf) || i >= maxSpan {
			return 0, false
		}
		if buf[i] != secret[j] {
			return 0, false
		}
		i++
		j++
		end = i
	}
}

// emit writes data to the underlying writer, respecting the maxOut cap.
func (w *Writer) emit(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if w.maxOut > 0 {
		remaining := w.maxOut - w.written
		if remaining <= 0 {
			return nil
		}
		if int64(len(data)) > remaining {
			data = data[:remaining]
		}
	}
	n, err := w.out.Write(data)
	w.written += int64(n)
	return err
}

// BytesWritten returns the number of bytes written to the underlying writer.
func (w *Writer) BytesWritten() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written
}

// RedactionCount returns the number of secret occurrences replaced so far.
func (w *Writer) RedactionCount() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.redactions
}

// AddSecret registers an additional secret value for redaction.
// Thread-safe; can be called after the writer is in use.
func (w *Writer) AddSecret(s string) {
	if s == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addSecretLocked([]byte(s))
}

// addSecretLocked registers b and rebuilds the match indexes.
// Callers must hold w.mu (or be inside New).
func (w *Writer) addSecretLocked(b []byte) {
	w.secrets = append(w.secrets, b)
	if len(b) > w.maxLen {
		w.maxLen = len(b)
	}
	if s := flexSpanCap(len(b)); s > w.maxSpan {
		w.maxSpan = s
	}
	// Re-sort longest-first for greedy matching, then rebuild indexes.
	sort.Slice(w.secrets, func(i, j int) bool {
		return len(w.secrets[i]) > len(w.secrets[j])
	})
	w.byFirst = make(map[byte][]int)
	w.fragments = make(map[[fragmentLen]byte]fragHit)
	for i, s := range w.secrets {
		w.byFirst[s[0]] = append(w.byFirst[s[0]], i)
		if len(s) >= fragmentMinSecretLen && len(s) <= fragmentMaxSecretLen {
			for off := 0; off+fragmentLen <= len(s); off++ {
				var key [fragmentLen]byte
				copy(key[:], s[off:off+fragmentLen])
				w.fragments[key] = fragHit{secret: s, off: off}
			}
		}
	}
}

// hasPrefix reports whether b starts with prefix.
func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i, c := range prefix {
		if b[i] != c {
			return false
		}
	}
	return true
}
