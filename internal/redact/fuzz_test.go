// Fuzz harness for the streaming redactor (Phase 0, item 0.5).
//
// Invariants checked for every input:
//  1. No registered value (secret or derived variant) appears literally in
//     the output.
//  2. No contiguous run of fragmentLen (12) or more bytes of any long
//     registered value (>= fragmentMinSecretLen) survives in the output —
//     this is the fragment-matching guarantee: truncated/pasted fragments
//     of long secrets are always redacted.
//
// Inputs are written in deterministic uneven chunks to exercise secrets
// straddling Write boundaries, including whitespace/control-tolerant matches
// split across chunks.
package redact

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

var fuzzSecrets = []string{
	"sk-live-9f8e7d6c5b4a3948271605a4b3c2d1e0f12",  // 42 chars
	"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd", // 40 chars
	"xoxb-13579246801357924680135792468013579246",  // 42 chars
}

// fuzzAllValues returns every registered value: the secrets plus all derived
// encodings, mirroring what the runner registers.
func fuzzAllValues() []string {
	all := append([]string{}, fuzzSecrets...)
	for _, s := range fuzzSecrets {
		all = append(all, Encodings(s, 8)...)
	}
	return all
}

// interleaveFuzz inserts a gap byte between every character of s.
func interleaveFuzz(s string, gap byte) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		if i > 0 {
			b.WriteByte(gap)
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// chunkSplit deterministically splits data into uneven chunks to exercise
// cross-Write-boundary matching.
func chunkSplit(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	sizes := []int{1, 2, 5, 13, 7, 3}
	var chunks [][]byte
	i, k := 0, 0
	for i < len(data) {
		n := sizes[k%len(sizes)]
		k++
		if i+n > len(data) {
			n = len(data) - i
		}
		chunks = append(chunks, data[i:i+n])
		i += n
	}
	return chunks
}

// hasSubstrLen reports whether out contains any contiguous n-byte substring
// of v.
func hasSubstrLen(out []byte, v string, n int) bool {
	if len(v) < n || len(out) < n {
		return false
	}
	windows := make(map[[12]byte]struct{}, len(v))
	vb := []byte(v)
	for i := 0; i+n <= len(vb); i++ {
		var k [12]byte
		copy(k[:], vb[i:i+n])
		windows[k] = struct{}{}
	}
	for i := 0; i+n <= len(out); i++ {
		var k [12]byte
		copy(k[:], out[i:i+n])
		if _, ok := windows[k]; ok {
			return true
		}
	}
	return false
}

// hexEncodeFuzz is a test-local hex encoder.
func hexEncodeFuzz(s string) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		b.WriteByte(digits[s[i]>>4])
		b.WriteByte(digits[s[i]&0x0f])
	}
	return b.String()
}

func FuzzRedact(f *testing.F) {
	s0 := fuzzSecrets[0]
	b64 := base64.StdEncoding.EncodeToString([]byte(s0))

	seeds := [][]byte{
		[]byte("prefix " + s0 + " suffix"),
		[]byte(b64),
		[]byte(`{"token": "` + b64 + `"}`),
		[]byte(base64.StdEncoding.EncodeToString([]byte(b64))), // b64(b64(v))
		[]byte(url.QueryEscape(b64)),                           // %XX uppercase
		[]byte(lowerPctEscapes(url.QueryEscape(b64))),          // %xx lowercase
		[]byte(wrapLines(b64, 64)),                             // openssl 64-col wrap
		[]byte(wrapLines(b64, 76)),                             // MIME 76-col wrap
		[]byte(interleaveFuzz(s0, 0x1b)),                       // ESC smuggling
		[]byte(interleaveFuzz(s0, '\n')),                       // newline split
		[]byte(interleaveFuzz(s0, 0x00)),                       // NUL smuggling
		[]byte(s0[7:27]),                                       // 20-char fragment
		[]byte(s0[:12]),                                        // exactly-12 fragment
		[]byte(s0[:20] + "\x01\x02" + s0[20:]),                 // control bytes inside
		[]byte("key=" + b64 + ";next"),                         // affixed value
		[]byte(base64.URLEncoding.EncodeToString([]byte(s0))),  // url-safe b64
		[]byte(strings.ToUpper(hexEncodeFuzz(s0))),             // upper hex
		[]byte(url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(b64)))),
	}
	for _, sd := range seeds {
		f.Add(sd)
	}

	all := fuzzAllValues()
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		w := New(&buf, all, 0)
		for _, c := range chunkSplit(data) {
			if _, err := w.Write(c); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		out := buf.Bytes()
		for _, v := range all {
			if bytes.Contains(out, []byte(v)) {
				t.Errorf("registered value leaked: %q in output %q", v, out)
			}
			if len(v) >= fragmentMinSecretLen && hasSubstrLen(out, v, fragmentLen) {
				t.Errorf("fragment of registered value survived: value %q in output %q", v, out)
			}
		}
	})
}
