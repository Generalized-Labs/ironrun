package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMCPRegistrationPreservesExistingEntriesAndValues(t *testing.T) {
	for _, tc := range []struct {
		name, entry, state string
	}{
		{"recognized", `{"command":"ironrun","args":["mcp"]}`, "configuration recognized"},
		{"custom", `{"command":"custom-server","args":["serve"]}`, "needs inspection"},
		{"disabled", `{"command":"ironrun","args":["mcp"],"disabled":true}`, "needs inspection"},
		{"remote transport", `{"type":"http","url":"https://example.invalid/mcp","command":"ironrun","args":["mcp"]}`, "needs inspection"},
		{"invalid entry", `null`, "needs inspection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mcp.json")
			original := `{"otherSetting":1e1000,"mcpServers":{"ironrun":` + tc.entry + `,"other":{"command":"other-server"}}}`
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			result := registerJSONMCP("test client", path, "fixture config")
			if result.err != nil || result.state != tc.state {
				t.Fatalf("unexpected registration status: %+v", result)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != original {
				t.Fatalf("existing entry or setting changed: %q %v", after, err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(`{"otherSetting":1e1000,"mcpServers":{"other":{"command":"other-server"}}}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	result := registerJSONMCP("test client", path, "fixture config")
	if result.err != nil || result.state != "configuration written" {
		t.Fatalf("could not merge valid config: %+v", result)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if string(config["otherSetting"]) != "1e1000" {
		t.Fatalf("unrelated number changed: %s", config["otherSetting"])
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(config["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	if _, ok := servers["other"]; !ok {
		t.Fatal("existing server lost")
	}
	if _, ok := servers["ironrun"]; !ok {
		t.Fatal("new registration missing")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("existing file permissions changed: %v %v", info, err)
	}
}

func TestMCPRegistrationPreservesReadOnlyConfiguration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root file permission enforcement")
	}
	path := filepath.Join(t.TempDir(), "mcp.json")
	original := `{"otherSetting":true,"mcpServers":{"other":{"command":"other-server"}}}`
	if err := os.WriteFile(path, []byte(original), 0400); err != nil {
		t.Fatal(err)
	}
	result := registerJSONMCP("test client", path, "fixture config")
	if result.err == nil {
		t.Fatal("registration bypassed read-only configuration")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != original {
		t.Fatalf("read-only config changed: %q %v", after, err)
	}
}

func TestMCPRegistrationPreservesInvalidConfiguration(t *testing.T) {
	for _, target := range []string{"claude", "cursor"} {
		for _, contents := range []string{"null", "[]", `{`, `{"otherSetting":true,"mcpServers":null}`, `{"otherSetting":true,"mcpServers":[]}`} {
			t.Run(target+"/"+contents, func(t *testing.T) {
				root := t.TempDir()
				t.Setenv("HOME", root)
				path := filepath.Join(root, ".mcp.json")
				register := func() error { return registerClaudeMCP(root) }
				if target == "cursor" {
					path = filepath.Join(root, ".cursor", "mcp.json")
					register = registerCursor
				}
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				var registerErr error
				var panicValue any
				func() {
					defer func() { panicValue = recover() }()
					registerErr = register()
				}()
				if panicValue != nil {
					t.Errorf("registration panicked on existing configuration: %v", panicValue)
				}
				if registerErr == nil {
					t.Error("registration accepted invalid existing configuration")
				}
				after, err := os.ReadFile(path)
				if err != nil || string(after) != contents {
					t.Fatalf("existing configuration changed: %q, %v", after, err)
				}
			})
		}
	}
}

func TestMCPRegistrationPreservesUnreadableWritableConfiguration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root user to exercise file read permissions")
	}
	for _, target := range []string{"claude", "cursor"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			path := filepath.Join(root, ".mcp.json")
			register := func() error { return registerClaudeMCP(root) }
			if target == "cursor" {
				path = filepath.Join(root, ".cursor", "mcp.json")
				register = registerCursor
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			contents := `{"otherSetting":true,"mcpServers":{"other":{"command":"other-server"}}}`
			if err := os.WriteFile(path, []byte(contents), 0200); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(path, 0600)
			if _, err := os.ReadFile(path); err == nil {
				t.Fatal("fixture must be unreadable")
			}
			if err := register(); err == nil {
				t.Error("registration ignored an existing configuration read failure")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != contents {
				t.Fatalf("unreadable existing configuration was overwritten: %q, %v", after, err)
			}
		})
	}
}
