// Command eval reproduces the measurements in paper/ironrun.tex.
//
//	go run ./paper/eval            # all experiments, LaTeX-ready rows on stdout
//	go run ./paper/eval -only leak # one experiment: leak | fp | perf
//
// Leak experiment: every (secret, transformation) pair is printed by a real
// child process run through runner.Run — the same injection, pipe, redaction,
// and encoding registration a sealed run uses. The agent-visible output is
// then attacked with a battery of decoders (identity, gap stripping, case
// folding, reversal, ROT13, base64/hex at every alignment, URL/JSON
// unescaping, gunzip). "Recovered" is the longest contiguous run of secret
// bytes any decoder yields; a pair counts as a leak when >= 50% of the secret
// is recoverable.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/redact"
	"github.com/generalized-labs/ironrun/internal/runner"
)

type secret struct{ name, value string }

// Synthetic credentials shaped like the real formats (deterministic seed).
func secrets() []secret {
	r := rand.New(rand.NewSource(7))
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	rs := func(n int, alpha string) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[r.Intn(len(alpha))]
		}
		return string(b)
	}
	return []secret{
		{"stripe", "sk_live_" + rs(24, alnum)},
		{"github", "ghp_" + rs(36, alnum)},
		{"aws", rs(40, alnum+"+/")},
		{"pg-url", "postgres://app:" + rs(16, alnum) + "@db.internal:5432/app?sslmode=require&pool=5"},
		{"password", rs(12, alnum+"!#%&*")},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9." + rs(48, alnum+"-_") + "." + rs(43, alnum+"-_")},
	}
}

type transform struct {
	name, class string
	f           func(s string) string
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func wrap(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		b.WriteString(s[i:min(i+n, len(s))])
		b.WriteByte('\n')
	}
	return b.String()
}

func gz(s string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return buf.String()
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func xxd(s string) string {
	var b strings.Builder
	data := []byte(s)
	for off := 0; off < len(data); off += 16 {
		line := data[off:min(off+16, len(data))]
		fmt.Fprintf(&b, "%08x: ", off)
		for i := 0; i < 16; i++ {
			if i < len(line) {
				fmt.Fprintf(&b, "%02x", line[i])
			} else {
				b.WriteString("  ")
			}
			if i%2 == 1 {
				b.WriteByte(' ')
			}
		}
		for _, c := range line {
			if c < 0x20 || c > 0x7e {
				c = '.'
			}
			b.WriteByte(c)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func transforms() []transform {
	return []transform{
		// Accidental: what ordinary debugging commands print.
		{"printenv line", "accidental", func(s string) string { return "API_KEY=" + s }},
		{"xtrace (set -x)", "accidental", func(s string) string { return "+ curl -H 'Authorization: Bearer " + s + "' https://api" }},
		{"JSON (Go encoder)", "accidental", func(s string) string { j, _ := json.Marshal(map[string]string{"dsn": s}); return string(j) }},
		{"URL query param", "accidental", func(s string) string { return "GET /cb?token=" + url.QueryEscape(s) }},
		{"HTTP Basic auth", "accidental", func(s string) string { return "> Authorization: Basic " + b64("deploy:"+s) }},
		{"k8s Secret (base64)", "accidental", func(s string) string { return "data:\n  key: " + b64(s) }},
		{"printenv | base64", "accidental", func(s string) string { return wrap(b64("HOME=/home/dev\nAPI_KEY="+s+"\nSHELL=/bin/zsh\n"), 76) }},
		{"xxd hexdump", "accidental", func(s string) string { return xxd("API_KEY=" + s + "\n") }},
		{"ANSI-highlighted", "accidental", func(s string) string {
			h := len(s) / 2
			return "\x1b[32m" + s[:h] + "\x1b[0m\x1b[33m" + s[h:] + "\x1b[0m"
		}},
		{"pty wrap (CRLF)", "accidental", func(s string) string { h := len(s) / 3; return "token: " + s[:h] + "\r\n" + s[h:] }},
		{"UTF-16LE", "accidental", func(s string) string {
			var b bytes.Buffer
			for _, u := range utf16.Encode([]rune(s)) {
				b.WriteByte(byte(u))
				b.WriteByte(byte(u >> 8))
			}
			return b.String()
		}},
		{"truncated log (first 60%)", "accidental", func(s string) string { return "key=" + s[:len(s)*6/10] + "..." }},
		// Deliberate: an agent (or injected prompt) trying to smuggle it out.
		{"hex", "deliberate", func(s string) string { return hex.EncodeToString([]byte(s)) }},
		{"base64 at offset 1", "deliberate", func(s string) string { return b64("x" + s) }},
		{"double base64", "deliberate", func(s string) string { return b64(b64(s)) }},
		{"gzip | base64", "deliberate", func(s string) string { return b64(gz(s)) }},
		{"reversed", "deliberate", reverse},
		{"ROT13", "deliberate", rot13},
		{"one char per line", "deliberate", func(s string) string { return strings.Join(strings.Split(s, ""), "\n") }},
		{"split with separator", "deliberate", func(s string) string { h := len(s) / 2; return s[:h] + "-|-" + s[h:] }},
		{"upper-cased", "deliberate", strings.ToUpper},
	}
}

// ---- decoders: everything an analyst might try on the redacted output ----

var (
	b64Run = regexp.MustCompile(`[A-Za-z0-9+/=_-]{8,}`)
	hexRun = regexp.MustCompile(`[0-9a-fA-F]{8,}`)
	jsonU  = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

func stripGaps(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(s, ""))
}

func decodeB64Runs(s string) []string {
	var out []string
	for _, run := range b64Run.FindAllString(s, -1) {
		run = strings.TrimRight(run, "=")
		std := strings.NewReplacer("-", "+", "_", "/").Replace(run)
		for off := 0; off < 4 && off < len(std); off++ {
			chunk := std[off:]
			if len(chunk)%4 == 1 { // the only invalid unpadded length
				chunk = chunk[:len(chunk)-1]
			}
			if d, err := base64.RawStdEncoding.DecodeString(chunk); err == nil {
				out = append(out, string(d))
			}
		}
	}
	return out
}

func decodeHexRuns(s string) []string {
	var out []string
	for _, run := range hexRun.FindAllString(s, -1) {
		for off := 0; off < 2 && off < len(run); off++ {
			chunk := run[off:]
			chunk = chunk[:len(chunk)/2*2]
			if d, err := hex.DecodeString(chunk); err == nil {
				out = append(out, string(d))
			}
		}
	}
	// xxd: rebuild the byte stream from the hex columns.
	var col strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, ": "); i == 8 && len(line) >= 50 {
			col.WriteString(strings.ReplaceAll(line[10:49], " ", ""))
		}
	}
	if d, err := hex.DecodeString(col.String()[:col.Len()/2*2]); err == nil && col.Len() > 0 {
		out = append(out, string(d))
	}
	return out
}

func gunzip(s string) string {
	r, err := gzip.NewReader(strings.NewReader(s))
	if err != nil {
		return ""
	}
	var b bytes.Buffer
	b.ReadFrom(r) // partial output on corruption is still evidence
	return b.String()
}

func candidates(out string) []string {
	c := []string{out, stripGaps(out), strings.ToLower(out), reverse(out), rot13(out)}
	if u, err := url.QueryUnescape(out); err == nil {
		c = append(c, u)
	}
	c = append(c, jsonU.ReplaceAllStringFunc(out, func(m string) string {
		n, _ := strconv.ParseUint(m[2:], 16, 16)
		return string(rune(n))
	}))
	c = append(c, strings.ReplaceAll(out, "\x00", ""))
	lines := strings.Split(out, "\n")
	c = append(c, strings.Join(lines, ""))
	var nested []string
	for _, x := range c {
		for _, d := range decodeB64Runs(x) {
			nested = append(nested, d)
			if i := strings.Index(d, "\x1f\x8b"); i >= 0 {
				nested = append(nested, gunzip(d[i:]))
			}
			nested = append(nested, decodeB64Runs(d)...)
		}
		nested = append(nested, decodeHexRuns(x)...)
	}
	return append(c, nested...)
}

// recovered returns the longest contiguous run of secret bytes any decoder
// recovers from out (case-insensitively, so case folding is not a disguise).
func recovered(out, s string) int {
	ls := strings.ToLower(s)
	best := 0
	for _, c := range candidates(out) {
		lc := strings.ToLower(c)
		for i := 0; i < len(ls); i++ {
			for j := len(ls); j-i > best; j-- {
				if strings.Contains(lc, ls[i:j]) {
					best = j - i
					break
				}
			}
		}
	}
	return best
}

// runSealed prints payload from a real child process through runner.Run with
// value injected as API_KEY, exactly as a sealed command would.
func runSealed(dir, value, payload string) (*runner.Result, error) {
	f := filepath.Join(dir, "payload")
	if err := os.WriteFile(f, []byte("starting job\n"+payload+"\ndone\n"), 0o600); err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := &policy.Command{ID: "eval", Argv: []string{"cat", f}, AllowNetwork: true}
	return runner.Run(context.Background(), cmd, runner.Options{
		Stdout: &stdout, Stderr: &stderr, Secrets: map[string]string{"API_KEY": value},
	})
}

func leakExperiment() error {
	dir, err := os.MkdirTemp("", "ironrun-eval-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	ss := secrets()
	fmt.Println("% leak experiment: transformation & class & leaked/secrets & mean recovered % & entropy-flagged")
	totalLeaks, total := 0, 0
	for _, t := range transforms() {
		leaks, flagged := 0, 0
		var pct float64
		for _, s := range ss {
			res, err := runSealed(dir, s.value, t.f(s.value))
			if err != nil {
				return fmt.Errorf("%s/%s: %w", t.name, s.name, err)
			}
			rec := recovered(res.Stdout, s.value)
			p := float64(rec) / float64(len(s.value))
			pct += p
			if p >= 0.5 {
				leaks++
				if res.EntropyWarnings > 0 {
					flagged++
				}
			}
		}
		total += len(ss)
		totalLeaks += leaks
		fmt.Printf("%-28s & %-10s & %d/%d & %5.1f\\%% & %d \\\\\n", t.name, t.class, leaks, len(ss), 100*pct/float64(len(ss)), flagged)
	}
	fmt.Printf("%% total: %d/%d pairs leak >=50%% of the secret\n", totalLeaks, total)
	return nil
}

// fpExperiment counts redactions on benign text (the repository's own
// sources and docs) for random vs. structured secrets. Every redaction here
// is a false positive.
func fpExperiment() error {
	var corpus bytes.Buffer
	filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && (d.Name() == ".claude" || d.Name() == ".git" || d.Name() == "paper") {
			return filepath.SkipDir
		}
		if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".go") || strings.HasSuffix(p, ".md")) {
			b, _ := os.ReadFile(p)
			corpus.Write(b)
		}
		return nil
	})
	// Plus log lines that share structure with a connection URL.
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&corpus, "INFO connecting to db.internal:5432/app?sslmode=require attempt=%d\n", i)
	}
	fmt.Printf("%% fp experiment: corpus %d bytes\n", corpus.Len())
	for _, s := range secrets() {
		pats := append([]string{s.value}, redact.Encodings(s.value, 8)...)
		var out bytes.Buffer
		w := redact.New(&out, pats, 0)
		w.Write(corpus.Bytes())
		w.Flush()
		fmt.Printf("%-10s & %d patterns & %d false-positive redactions \\\\\n", s.name, len(pats), w.RedactionCount())
	}
	return nil
}

func median(d []time.Duration) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2]
}

func perfExperiment() error {
	// Throughput of the streaming redactor on 4 MiB of log-like text, with N
	// injected secrets each expanded into its registered encodings.
	line := []byte("2026-10-09T12:00:00Z INFO request served path=/api/v1/items status=200 dur=3.2ms\n")
	data := bytes.Repeat(line, 4<<20/len(line))
	fmt.Println("% perf: secrets & patterns & MB/s (4 MiB, 32 KiB writes)")
	r := rand.New(rand.NewSource(1))
	for _, n := range []int{1, 10, 50} {
		var pats []string
		for i := 0; i < n; i++ {
			v := fmt.Sprintf("sk_live_%024x", r.Uint64())
			pats = append(pats, v)
			pats = append(pats, redact.Encodings(v, 8)...)
		}
		var best time.Duration
		for rep := 0; rep < 5; rep++ {
			w := redact.New(discard{}, pats, 0)
			start := time.Now()
			for off := 0; off < len(data); off += 32 << 10 {
				w.Write(data[off:min(off+32<<10, len(data))])
			}
			w.Flush()
			if el := time.Since(start); best == 0 || el < best {
				best = el
			}
		}
		fmt.Printf("%d & %d & %.0f \\\\\n", n, len(pats), float64(len(data))/best.Seconds()/1e6)
	}

	// End-to-end overhead: spawning `true` directly vs. through runner.Run.
	bin, _ := exec.LookPath("true")
	const reps = 200
	var direct, sealed, isolated []time.Duration
	sec := map[string]string{"API_KEY": "TEST-SECRET-0123456789abcdef0123"}
	for i := 0; i < reps; i++ {
		t := time.Now()
		exec.Command(bin).Run()
		direct = append(direct, time.Since(t))
		t = time.Now()
		runner.Run(context.Background(), &policy.Command{ID: "t", Argv: []string{bin}, AllowNetwork: true}, runner.Options{Stdout: discard{}, Stderr: discard{}, Secrets: sec})
		sealed = append(sealed, time.Since(t))
		t = time.Now()
		if _, err := runner.Run(context.Background(), &policy.Command{ID: "t", Argv: []string{bin}, NoNetwork: true}, runner.Options{Stdout: discard{}, Stderr: discard{}, Secrets: sec}); err == nil {
			isolated = append(isolated, time.Since(t))
		}
	}
	fmt.Printf("%% spawn median: direct %v, runner %v, runner+no_network %v (n=%d)\n", median(direct), median(sealed), medianOrNA(isolated), reps)
	return nil
}

func medianOrNA(d []time.Duration) string {
	if len(d) == 0 {
		return "n/a (isolation unavailable)"
	}
	return median(d).String()
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func main() {
	only := flag.String("only", "", "run one experiment: leak | fp | perf")
	flag.Parse()
	// The runner writes operator warnings (entropy hits, etc.) to stderr; keep
	// the table output clean.
	if null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stderr = null
	}
	exps := []struct {
		name string
		f    func() error
	}{{"leak", leakExperiment}, {"fp", fpExperiment}, {"perf", perfExperiment}}
	for _, e := range exps {
		if *only != "" && *only != e.name {
			continue
		}
		if err := e.f(); err != nil {
			fmt.Fprintln(os.Stdout, "error:", err)
			os.Exit(1)
		}
	}
}
