package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DetectedCmd is a command discovered for the generated policy.
type DetectedCmd struct {
	ID       string   // policy id (kebab-case)
	Argv     []string // exact argv — never a shell
	TTL      string   // "0" for long-running, else "120s"
	Comment  string   // human description, e.g. "npm run dev"
	NeedsEnv bool     // attach the detected env block to this command
}

const maxDetectedCommands = 20

var idRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// detectCommands inspects the project's task runners and language and returns a
// deduped, ordered list of sealed commands. Task-runner sources (package.json
// scripts, Makefile targets) take precedence over language defaults; the first
// detector to claim an id wins.
func detectCommands(dir string, envVars []string) []DetectedCmd {
	var cmds []DetectedCmd
	seen := map[string]bool{}
	add := func(c DetectedCmd) {
		if c.ID == "" || seen[c.ID] || len(cmds) >= maxDetectedCommands {
			return
		}
		seen[c.ID] = true
		cmds = append(cmds, c)
	}

	// Task runners first (what the human actually uses).
	for _, c := range detectNode(dir) {
		add(c)
	}
	for _, c := range detectMake(dir) {
		add(c)
	}
	// Language defaults fill only ids not already claimed.
	for _, c := range detectGo(dir) {
		add(c)
	}
	for _, c := range detectRust(dir) {
		add(c)
	}
	for _, c := range detectPython(dir) {
		add(c)
	}

	if len(envVars) > 0 {
		for i := range cmds {
			cmds[i].NeedsEnv = needsEnv(cmds[i].ID)
		}
	}
	return cmds
}

// needsEnv decides whether a command likely needs credentials injected.
func needsEnv(id string) bool {
	switch id {
	case "dev", "start", "serve", "test", "deploy", "migrate", "seed":
		return true
	}
	return strings.HasPrefix(id, "integration") || strings.HasPrefix(id, "e2e")
}

func ttlFor(id string) string {
	switch id {
	case "dev", "start", "serve", "watch":
		return "0" // long-running
	}
	return "120s"
}

func fileExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func sanitizeID(s string) string {
	return strings.Trim(idRe.ReplaceAllString(s, "-"), "-")
}

// detectNode reads package.json scripts and maps each to `<runner> run <name>`
// (or `<runner> test` for the conventional `test` script).
func detectNode(dir string) []DetectedCmd {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &pkg) != nil || len(pkg.Scripts) == 0 {
		return nil
	}
	runner := nodeRunner(dir)
	names := make([]string, 0, len(pkg.Scripts))
	for n := range pkg.Scripts {
		names = append(names, n)
	}
	sort.Strings(names)

	var cmds []DetectedCmd
	for _, name := range names {
		id := sanitizeID(name)
		if id == "" {
			continue
		}
		argv := []string{runner, "run", name}
		if name == "test" {
			argv = []string{runner, "test"} // conventional
		}
		cmds = append(cmds, DetectedCmd{ID: id, Argv: argv, TTL: ttlFor(id), Comment: strings.Join(argv, " ")})
	}
	return cmds
}

func nodeRunner(dir string) string {
	switch {
	case fileExists(dir, "bun.lockb"), fileExists(dir, "bun.lock"):
		return "bun"
	case fileExists(dir, "pnpm-lock.yaml"):
		return "pnpm"
	case fileExists(dir, "yarn.lock"):
		return "yarn"
	}
	return "npm"
}

var makeTargetRe = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_-]*):`)

// detectMake parses simple Makefile target names into `make <target>` commands.
func detectMake(dir string) []DetectedCmd {
	var data []byte
	for _, n := range []string{"Makefile", "makefile", "GNUmakefile"} {
		if d, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			data = d
			break
		}
	}
	if data == nil {
		return nil
	}
	var cmds []DetectedCmd
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		m := makeTargetRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		target := m[1]
		if seen[target] {
			continue
		}
		seen[target] = true
		id := sanitizeID(target)
		cmds = append(cmds, DetectedCmd{ID: id, Argv: []string{"make", target}, TTL: ttlFor(id), Comment: "make " + target})
	}
	return cmds
}

func detectGo(dir string) []DetectedCmd {
	if !fileExists(dir, "go.mod") {
		return nil
	}
	return []DetectedCmd{
		{ID: "test", Argv: []string{"go", "test", "./..."}, TTL: "120s", Comment: "go test ./..."},
		{ID: "build", Argv: []string{"go", "build", "./..."}, TTL: "120s", Comment: "go build ./..."},
	}
}

func detectRust(dir string) []DetectedCmd {
	if !fileExists(dir, "Cargo.toml") {
		return nil
	}
	return []DetectedCmd{
		{ID: "test", Argv: []string{"cargo", "test"}, TTL: "120s", Comment: "cargo test"},
		{ID: "build", Argv: []string{"cargo", "build"}, TTL: "120s", Comment: "cargo build"},
	}
}

func detectPython(dir string) []DetectedCmd {
	if !fileExists(dir, "pyproject.toml") && !fileExists(dir, "requirements.txt") {
		return nil
	}
	return []DetectedCmd{
		{ID: "test", Argv: []string{"python", "-m", "pytest"}, TTL: "120s", Comment: "python -m pytest"},
	}
}

// yamlArgvItem quotes an argv element when it contains characters that would
// break a YAML flow sequence (colons, commas, brackets, spaces, quotes).
func yamlArgvItem(s string) string {
	if s == "" || strings.ContainsAny(s, ":,[]{}#\"' \t\n") {
		return strconv.Quote(s)
	}
	return s
}

// renderCommandBlock renders a single YAML command list item. It is the single
// source of truth for policy command formatting — used by `init` (generated
// policies) and by `approve` (merging an approved proposal).
func renderCommandBlock(id string, argv []string, ttl string, env map[string]string, comment string) string {
	var b strings.Builder
	if comment != "" {
		fmt.Fprintf(&b, "  # %s\n", comment)
	}
	fmt.Fprintf(&b, "  - id: %s\n", id)
	items := make([]string, len(argv))
	for i, a := range argv {
		items[i] = yamlArgvItem(a)
	}
	fmt.Fprintf(&b, "    argv: [%s]\n", strings.Join(items, ", "))
	if ttl != "" {
		fmt.Fprintf(&b, "    ttl: %s\n", ttl)
	}
	if len(env) > 0 {
		b.WriteString("    env:\n")
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "      %s: %s\n", k, env[k])
		}
	}
	return b.String()
}
