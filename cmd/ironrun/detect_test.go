package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func cmdsByID(cmds []DetectedCmd) map[string]DetectedCmd {
	m := map[string]DetectedCmd{}
	for _, c := range cmds {
		m[c.ID] = c
	}
	return m
}

func TestDetectCommands_NodeScripts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"scripts":{"dev":"vite","test":"vitest","build":"x","lint":"eslint"}}`)
	got := cmdsByID(detectCommands(dir, nil))
	if c := got["dev"]; len(c.Argv) != 3 || c.Argv[2] != "dev" || c.TTL != "0" {
		t.Errorf("dev: %+v", c)
	}
	if c := got["test"]; len(c.Argv) != 2 || c.Argv[1] != "test" {
		t.Errorf("test should be [npm test]: %+v", c)
	}
	if _, ok := got["lint"]; !ok {
		t.Error("lint script not detected")
	}
}

func TestDetectCommands_TaskRunnerWinsDedup(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"scripts":{"test":"vitest"}}`)
	writeFile(t, dir, "Makefile", "test:\n\techo hi\nlint:\n\techo lint\n")
	got := cmdsByID(detectCommands(dir, nil))
	if c := got["test"]; len(c.Argv) == 0 || c.Argv[0] != "npm" {
		t.Errorf("expected node test to win precedence, got %v", c.Argv)
	}
	if _, ok := got["lint"]; !ok {
		t.Error("make-only target lint should be detected")
	}
}

func TestDetectCommands_GoDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module x\n\ngo 1.26\n")
	got := cmdsByID(detectCommands(dir, nil))
	if c := got["test"]; len(c.Argv) != 3 || c.Argv[0] != "go" {
		t.Errorf("go test: %+v", c)
	}
}

func TestDetectCommands_EnvHeuristic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"scripts":{"dev":"vite","build":"x"}}`)
	m := cmdsByID(detectCommands(dir, []string{"DATABASE_URL"}))
	if !m["dev"].NeedsEnv {
		t.Error("dev should need env")
	}
	if m["build"].NeedsEnv {
		t.Error("build should NOT need env")
	}
}

func TestRenderCommandBlock_QuotesSpecialArgv(t *testing.T) {
	out := renderCommandBlock("db", []string{"psql", "postgres://localhost/db"}, "120s", nil, "")
	if !strings.Contains(out, `"postgres://localhost/db"`) {
		t.Errorf("expected the url argv to be quoted, got:\n%s", out)
	}
}
