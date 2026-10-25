// Package tests contains integration tests for the ironrun CLI.
package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// ironrunBin is the path to the compiled ironrun binary used in tests.
var (
	ironrunBin   string
	buildBinOnce sync.Once
	buildBinErr  error
)

func buildBinary(t *testing.T) string {
	t.Helper()
	buildBinOnce.Do(func() {
		// Create a stable temp dir for the binary (not t.TempDir() which is per-test).
		dir, err := os.MkdirTemp("", "ironrun-test-bin-*")
		if err != nil {
			buildBinErr = fmt.Errorf("could not create temp dir: %w", err)
			return
		}
		bin := filepath.Join(dir, "ironrun")
		// The tests/ directory is one level below the module root.
		repoRoot, err := filepath.Abs("..")
		if err != nil {
			buildBinErr = fmt.Errorf("could not determine repo root: %w", err)
			return
		}
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/ironrun")
		cmd.Dir = repoRoot
		out, buildErr := cmd.CombinedOutput()
		if buildErr != nil {
			buildBinErr = fmt.Errorf("build failed: %w\n%s", buildErr, out)
			return
		}
		ironrunBin = bin
	})
	if buildBinErr != nil {
		t.Fatalf("could not build ironrun binary: %v", buildBinErr)
	}
	return ironrunBin
}

// runInit runs `ironrun init` in the given directory and returns combined output and error.
func runInit(t *testing.T, dir string) (string, error) {
	t.Helper()
	bin := buildBinary(t)
	cmd := exec.Command(bin, "init")
	cmd.Dir = dir
	testHome := filepath.Join(dir, ".test-home")
	if err := os.MkdirAll(testHome, 0700); err != nil {
		return "", err
	}
	cmd.Env = append(os.Environ(), "HOME="+testHome, "IRONRUN_HOME="+filepath.Join(testHome, ".ironrun"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestInit_CreatesExpectedFiles verifies that ironrun init creates
// ironrun.yml, .mcp.json, and CLAUDE.md in the project directory.
func TestInit_CreatesExpectedFiles(t *testing.T) {
	dir := t.TempDir()

	out, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("ironrun init failed: %v\noutput: %s", err, out)
	}

	files := []string{
		"ironrun.yml",
		".mcp.json",
		"CLAUDE.md",
		"AGENTS.md",
		".cursorrules",
	}

	for _, f := range files {
		path := filepath.Join(dir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist, but it does not\ninit output:\n%s", f, out)
		}
	}
}

// TestInit_Idempotent verifies that running init twice does not error
// and does not overwrite existing files.
func TestInit_Idempotent(t *testing.T) {
	dir := t.TempDir()

	// First run
	out1, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("first ironrun init failed: %v\noutput: %s", err, out1)
	}

	// Capture mtime / content of files after first run
	ymlPath := filepath.Join(dir, "ironrun.yml")
	ymlContent1, err := os.ReadFile(ymlPath)
	if err != nil {
		t.Fatalf("could not read ironrun.yml after first init: %v", err)
	}

	// Second run
	out2, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("second ironrun init failed: %v\noutput: %s", err, out2)
	}

	// File content must not have changed
	ymlContent2, err := os.ReadFile(ymlPath)
	if err != nil {
		t.Fatalf("could not read ironrun.yml after second init: %v", err)
	}
	if string(ymlContent1) != string(ymlContent2) {
		t.Errorf("ironrun.yml was overwritten on second init run")
	}

	// Second run output should mention "already exists"
	if !strings.Contains(out2, "already exists") {
		t.Errorf("expected second init to report files already exist, got:\n%s", out2)
	}
}

// TestInit_YmlContainsProvider verifies that new workspaces use direct-entry
// policy version 2 while older version-1 policies remain supported.
func TestInit_YmlContainsProvider(t *testing.T) {
	dir := t.TempDir()

	out, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("ironrun init failed: %v\noutput: %s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(dir, "ironrun.yml"))
	if err != nil {
		t.Fatalf("could not read ironrun.yml: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("ironrun.yml is not valid YAML: %v\ncontent:\n%s", err, data)
	}

	version, ok := parsed["version"]
	if !ok {
		t.Fatalf("ironrun.yml has no 'version' field\ncontent:\n%s", data)
	}

	// version is stored as string "2" in YAML (quoted)
	versionStr, ok := version.(string)
	if !ok {
		t.Fatalf("version field is not a string, got %T = %v", version, version)
	}
	if versionStr != "2" {
		t.Errorf("expected version=2, got %q\ncontent:\n%s", versionStr, data)
	}
}

// TestInit_ClaudeMcpJsonValid verifies that .mcp.json (the project-root file
// Claude Code actually reads) is valid JSON with mcpServers.ironrun.command == "ironrun".
func TestInit_ClaudeMcpJsonValid(t *testing.T) {
	dir := t.TempDir()

	out, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("ironrun init failed: %v\noutput: %s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".mcp.json"))
	if err != nil {
		t.Fatalf("could not read .mcp.json: %v", err)
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf(".mcp.json is not valid JSON: %v\ncontent:\n%s", err, data)
	}

	mcpServers, ok := config["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("mcpServers key missing or wrong type in .mcp.json\ncontent:\n%s", data)
	}

	ironrun, ok := mcpServers["ironrun"].(map[string]any)
	if !ok {
		t.Fatalf("mcpServers.ironrun missing or wrong type\ncontent:\n%s", data)
	}

	command, ok := ironrun["command"].(string)
	if !ok {
		t.Fatalf("mcpServers.ironrun.command missing or not a string\ncontent:\n%s", data)
	}
	if command != "ironrun" {
		t.Errorf("expected mcpServers.ironrun.command=ironrun, got %q", command)
	}
}

// TestInit_MergesExistingMcpJson verifies that init preserves MCP servers a user
// already has in .mcp.json and adds ironrun alongside them (no clobber).
func TestInit_MergesExistingMcpJson(t *testing.T) {
	dir := t.TempDir()

	existing := `{
  "mcpServers": {
    "other": { "command": "other-server", "args": ["serve"] }
  }
}

`
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("ironrun init failed: %v\noutput: %s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".mcp.json"))
	if err != nil {
		t.Fatalf("could not read .mcp.json: %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf(".mcp.json is not valid JSON: %v\ncontent:\n%s", err, data)
	}
	servers, ok := config["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("mcpServers missing\ncontent:\n%s", data)
	}
	if _, ok := servers["other"]; !ok {
		t.Errorf("existing 'other' MCP server was dropped on init\ncontent:\n%s", data)
	}
	if _, ok := servers["ironrun"]; !ok {
		t.Errorf("ironrun was not added to existing .mcp.json\ncontent:\n%s", data)
	}
}

func TestInit_RegistrationSummaryMatchesObservedResults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		list       string
		listFails  bool
		addFails   bool
		wantAdd    bool
		wantStatus string
	}{
		{"inspection failure", "", true, false, false, "Codex: needs attention"},
		{"invalid list", `null`, false, false, false, "Codex: needs attention"},
		{"null list entry", `[null]`, false, false, false, "Codex: needs attention"},
		{"empty list entry", `[{}]`, false, false, false, "Codex: needs attention"},
		{"missing record fields", `[{"name":"other"}]`, false, false, false, "Codex: needs attention"},
		{"add failure", `[]`, false, true, true, "Codex: needs attention"},
		{"substring is not registration", `[{"name":"other-ironrun-helper","enabled":true,"transport":{"type":"stdio","command":"other-server","args":["serve"]}}]`, false, false, true, "Codex: configuration written"},
		{"custom registration", `[{"name":"ironrun","enabled":true,"transport":{"type":"stdio","command":"custom-server","args":["serve"]}}]`, false, false, false, "Codex: needs inspection"},
		{"disabled registration", `[{"name":"ironrun","enabled":false,"transport":{"type":"stdio","command":"ironrun","args":["mcp"]}}]`, false, false, false, "Codex: needs inspection"},
		{"recognized registration", `[{"name":"ironrun","enabled":true,"transport":{"type":"stdio","command":"ironrun","args":["mcp"]}}]`, false, false, false, "Codex: configuration recognized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			binDir := filepath.Join(dir, "fake-bin")
			if err := os.Mkdir(binDir, 0700); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "codex-add.log")
			body := "#!/bin/sh\ncase \"$1 $2\" in\n'mcp list')\n"
			if tc.listFails {
				body += "exit 1\n"
			} else {
				body += "printf '%s\\n' '" + tc.list + "'\n"
			}
			body += ";;\n'mcp add') printf 'added\\n' > '" + logPath + "'\n"
			if tc.addFails {
				body += "exit 1\n"
			}
			body += ";;\nesac\n"
			if err := os.WriteFile(filepath.Join(binDir, "codex"), []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(dir, "fake-home")
			if err := os.Mkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(buildBinary(t), "setup", "--yes")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "HOME="+home, "IRONRUN_HOME="+filepath.Join(home, "ironrun"), "PATH="+binDir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("optional registration failure should preserve core setup success: %v\n%s", err, out)
			}
			_, statErr := os.Stat(logPath)
			if added := statErr == nil; added != tc.wantAdd {
				t.Errorf("Codex registration mutation: got added=%v want %v\n%s", added, tc.wantAdd, out)
			}
			if !strings.Contains(string(out), tc.wantStatus) {
				t.Errorf("missing accurate status %q:\n%s", tc.wantStatus, out)
			}
			if strings.Contains(string(out), "via MCP automatically") || strings.Contains(string(out), "registered above") {
				t.Errorf("setup claimed an unverified host connection:\n%s", out)
			}
		})
	}
}

func TestInit_MissingCodexIsNotReportedRegistered(t *testing.T) {
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty-path")
	if err := os.Mkdir(emptyPath, 0700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "fake-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(buildBinary(t), "setup", "--yes")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+home, "IRONRUN_HOME="+filepath.Join(home, "ironrun"), "PATH="+emptyPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("core setup failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Codex: CLI unavailable") || strings.Contains(string(out), "registered above") || strings.Contains(string(out), "via MCP automatically") {
		t.Fatalf("unavailable Codex summary is misleading:\n%s", out)
	}
}
