package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Output shapes that real tools produce from an injected value, found by the
// 2026-10 audit. Values are obviously synthetic.

const shapeSecret = "TEST-SECRET-0000-abcdefghijklmnop/qrst+uvw" // 42 bytes

// redactAsRunner registers v the way runner.Run does and redacts in.
func redactAsRunner(v, in string) string {
	var out bytes.Buffer
	w := New(&out, append([]string{v}, Encodings(v, 8)...), 0)
	w.Write([]byte(in))
	w.Flush()
	return out.String()
}

// longestRun is the longest substring of secret present in out.
func longestRun(out, secret string) int {
	best := 0
	for i := 0; i < len(secret); i++ {
		for j := len(secret); j-i > best; j-- {
			if strings.Contains(out, secret[i:j]) {
				best = j - i
				break
			}
		}
	}
	return best
}

func TestRedactBase64AtEveryAlignment(t *testing.T) {
	// HTTP Basic auth: base64("user:" + token). The token's offset mod 3
	// depends on the username, so every alignment must be covered.
	for _, user := range []string{"x-access-token", "u", "user", "oauth2", "ab"} {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			full := enc.EncodeToString([]byte(user + ":" + shapeSecret))
			out := redactAsRunner(shapeSecret, "> Authorization: Basic "+full+"\n")
			decoded := ""
			for off := 0; off < 4; off++ { // attacker tries every alignment
				body := strings.TrimPrefix(strings.TrimSuffix(out, "\n"), "> Authorization: Basic ")
				for _, piece := range strings.Split(body, placeholder) {
					if off < len(piece) {
						p := strings.TrimRight(piece[off:], "=")
						if len(p)%4 == 1 {
							p = p[:len(p)-1]
						}
						d, _ := base64.RawStdEncoding.DecodeString(strings.NewReplacer("-", "+", "_", "/").Replace(p))
						decoded += string(d) + "|"
					}
				}
			}
			if n := longestRun(decoded, shapeSecret); n >= 8 {
				t.Errorf("user %q: %d secret bytes decodable from %q", user, n, out)
			}
		}
	}
}

func TestRedactJSONAndPercentEncodings(t *testing.T) {
	v := "TEST-pw!*'(x)<y>&z/0000" // characters each encoder treats differently
	goJSON, _ := json.Marshal(v)   // escapes <, >, & as < etc.
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	jsURI := "TEST-pw!*'(x)%3Cy%3E%26z%2F0000"           // encodeURIComponent
	pyQuote := "TEST-pw%21%2A%27%28x%29%3Cy%3E%26z/0000" // urllib.parse.quote
	for name, shape := range map[string]string{
		"go json":            string(goJSON),
		"plain json":         strings.TrimSpace(plain.String()),
		"encodeURIComponent": jsURI,
		"python quote":       pyQuote,
		"python quote lower": strings.ToLower(pyQuote[:7]) + pyQuote[7:],
	} {
		if out := redactAsRunner(v, "value="+shape+"\n"); strings.Contains(out, "z/0000") || strings.Contains(out, "z%2F0000") || !strings.Contains(out, placeholder) {
			t.Errorf("%s form survived: %q", name, out)
		}
	}
}

func TestRedactHexDumpColumns(t *testing.T) {
	// xxd-style: offset, hex in 2-byte groups, ASCII column.
	data := []byte("API_KEY=" + shapeSecret + "\n")
	var dump strings.Builder
	for off := 0; off < len(data); off += 16 {
		line := data[off:min(off+16, len(data))]
		fmt.Fprintf(&dump, "%08x: ", off)
		for i, c := range line {
			fmt.Fprintf(&dump, "%02x", c)
			if i%2 == 1 {
				dump.WriteByte(' ')
			}
		}
		fmt.Fprintf(&dump, " %s\n", bytes.Map(func(r rune) rune {
			if r < 0x20 || r > 0x7e {
				return '.'
			}
			return r
		}, line))
	}
	out := redactAsRunner(shapeSecret, dump.String())
	var hexCol strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 10 {
			hexCol.WriteString(strings.ReplaceAll(strings.SplitN(line[10:], "  ", 2)[0], " ", ""))
		}
	}
	recovered, _ := hex.DecodeString(hexCol.String()[:hexCol.Len()/2*2])
	if n := longestRun(string(recovered)+"|"+out, shapeSecret); n*2 >= len(shapeSecret) {
		t.Errorf("hex dump leaks %d/%d secret bytes:\n%s", n, len(shapeSecret), out)
	}
}

func TestRedactLargeFileSecretFragments(t *testing.T) {
	// A ~3 KB multi-line file secret printed partially (one line of it).
	var b strings.Builder
	for i := 0; b.Len() < 3000; i++ {
		fmt.Fprintf(&b, "TEST-FILE-SECRET-LINE-%04d-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n", i)
	}
	secret := b.String()
	line := strings.Split(secret, "\n")[17]
	if out := redactAsRunner(secret, "grep: "+line+"\n"); longestRun(out, line) >= fragmentLen {
		t.Errorf("partial print of a large file secret survived: %q", out)
	}
}

func TestRedactWrappedBase64KeepsLineEnd(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(shapeSecret, 3)))
	var in strings.Builder // GNU base64: 76-column lines, then the next output line
	for i := 0; i < len(b64); i += 76 {
		in.WriteString(b64[i:min(i+76, len(b64))] + "\n")
	}
	in.WriteString("exit=0\n")
	if out := redactAsRunner(strings.Repeat(shapeSecret, 3), in.String()); !strings.HasSuffix(out, "\nexit=0\n") {
		t.Errorf("redaction swallowed the newline after wrapped base64: %q", out)
	}
}

func TestRedactSecretWithLeadingWhitespace(t *testing.T) {
	// A trimmed print of a value whose stored form starts with a newline.
	if out := redactAsRunner("\nTEST-pass-0000", "password=TEST-pass-0000\n"); strings.Contains(out, "TEST-pass") {
		t.Errorf("leading-gap secret survived: %q", out)
	}
}

func TestRedactBinaryFileSecretFragment(t *testing.T) {
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(0x80 + i) // invalid UTF-8 throughout
	}
	part := string(secret[20:50])
	if out := redactAsRunner(string(secret), "dump: "+part+"\n"); strings.Contains(out, part[:fragmentLen]) {
		t.Errorf("binary secret fragment survived")
	}
}

// Property 1 of the paper (chunking invariance): any split of the input into
// Write calls yields exactly the output of a single Write.
func TestStreamingMatchesBatch(t *testing.T) {
	secrets := []string{shapeSecret, "TEST-short-pw-0", "TEST-SECRET-9999-" + strings.Repeat("Zz", 40)}
	var pats []string
	for _, s := range secrets {
		pats = append(append(pats, s), Encodings(s, 8)...)
	}
	rng := rand.New(rand.NewSource(1))
	piece := func() string {
		p := pats[rng.Intn(len(pats))]
		switch rng.Intn(5) {
		case 0: // fragment
			i := rng.Intn(len(p))
			return p[i:min(len(p), i+1+rng.Intn(30))]
		case 1: // gap-interleaved
			return strings.Join(strings.Split(p, ""), []string{" ", "\n", "\r\n", "\x00"}[rng.Intn(4)])
		case 2:
			return "noise " + fmt.Sprint(rng.Int())
		}
		return p
	}
	for c := 0; c < 3000; c++ {
		var in strings.Builder
		for n := rng.Intn(6); n >= 0; n-- {
			in.WriteString(piece())
		}
		var batch, stream bytes.Buffer
		w := New(&batch, pats, 0)
		w.Write([]byte(in.String()))
		w.Flush()
		ws := New(&stream, pats, 0)
		for rest := in.String(); rest != ""; {
			k := min(len(rest), 1+rng.Intn(13))
			ws.Write([]byte(rest[:k]))
			rest = rest[k:]
		}
		ws.Flush()
		if batch.String() != stream.String() {
			t.Fatalf("case %d: streaming output diverged\nin:     %q\nbatch:  %q\nstream: %q", c, in.String(), batch.String(), stream.String())
		}
	}
}
