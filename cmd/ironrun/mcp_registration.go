package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type mcpRegistrationResult struct {
	client   string
	state    string
	location string
	next     string
	err      error
}

func printMCPRegistration(result mcpRegistrationResult) {
	fmt.Printf("  • %s: %s (%s)\n", result.client, result.state, result.location)
	if result.err != nil {
		fmt.Printf("    %v\n", result.err)
	}
	if result.next != "" {
		fmt.Printf("    Next: %s\n", result.next)
	}
}

func claudeMCPRegistration(cwd string) mcpRegistrationResult {
	return registerJSONMCP("Claude Code", filepath.Join(cwd, ".mcp.json"), ".mcp.json")
}

// Keep the existing entry point used by first-run TUI setup.
func registerClaudeMCP(cwd string) error {
	result := claudeMCPRegistration(cwd)
	printMCPRegistration(result)
	return result.err
}

func cursorMCPRegistration() mcpRegistrationResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return mcpRegistrationResult{client: "Cursor", state: "needs attention", location: "~/.cursor/mcp.json", err: err}
	}
	return registerJSONMCP("Cursor", filepath.Join(home, ".cursor", "mcp.json"), "~/.cursor/mcp.json")
}

func registerCursor() error {
	result := cursorMCPRegistration()
	printMCPRegistration(result)
	return result.err
}

// registerJSONMCP creates absent configuration or merges an absent Ironrun
// entry. A read/shape error or an existing custom entry never justifies replacing
// a user's configuration. RawMessage preserves unrelated values, including
// numbers that cannot be represented exactly as a float64.
func registerJSONMCP(client, path, location string) mcpRegistrationResult {
	result := mcpRegistrationResult{client: client, state: "needs attention", location: location,
		next: "Inspect " + location + " and rerun ironrun setup after resolving the configuration issue."}
	config := map[string]json.RawMessage{}
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(existing, &config); err != nil {
			result.err = fmt.Errorf("could not parse client configuration: %w", err)
			return result
		}
		if config == nil {
			result.err = fmt.Errorf("client configuration must be a JSON object")
			return result
		}
	case !os.IsNotExist(err):
		result.err = fmt.Errorf("could not read existing client configuration: %w", err)
		return result
	}
	servers := map[string]json.RawMessage{}
	if raw, exists := config["mcpServers"]; exists {
		if err := json.Unmarshal(raw, &servers); err != nil || servers == nil {
			result.err = fmt.Errorf("mcpServers must be a JSON object")
			return result
		}
	}
	if raw, exists := servers["ironrun"]; exists {
		if recognizedJSONMCP(raw) {
			result.state = "configuration recognized"
			result.next = ""
		} else {
			result.state = "needs inspection"
			result.next = "Inspect the existing ironrun entry in " + location + "; it was preserved without changes."
		}
		return result
	}
	servers["ironrun"] = json.RawMessage(`{"command":"ironrun","args":["mcp"]}`)
	config["mcpServers"], err = json.Marshal(servers)
	if err != nil {
		result.err = err
		return result
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		result.err = err
		return result
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		result.err = fmt.Errorf("could not create client configuration directory: %w", err)
		return result
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		result.err = fmt.Errorf("could not write client configuration: %w", err)
		return result
	}
	result.state, result.next = "configuration written", ""
	return result
}

func recognizedJSONMCP(raw json.RawMessage) bool {
	var entry struct {
		Type     string   `json:"type"`
		URL      string   `json:"url"`
		Command  string   `json:"command"`
		Args     []string `json:"args"`
		Enabled  *bool    `json:"enabled"`
		Disabled bool     `json:"disabled"`
	}
	if json.Unmarshal(raw, &entry) != nil {
		return false
	}
	return entry.Command == "ironrun" && len(entry.Args) == 1 && entry.Args[0] == "mcp" &&
		(entry.Type == "" || entry.Type == "stdio") && entry.URL == "" &&
		!entry.Disabled && (entry.Enabled == nil || *entry.Enabled)
}

func registerCodex() mcpRegistrationResult {
	result := mcpRegistrationResult{client: "Codex", state: "needs attention", location: "~/.codex/config.toml",
		next: "Inspect configured servers with codex mcp list --json before changing the ironrun registration."}
	codexBin, err := exec.LookPath("codex")
	if err != nil {
		result.state = "CLI unavailable"
		result.next = "After installing Codex, run codex mcp add ironrun -- ironrun mcp."
		return result
	}
	listOut, err := exec.Command(codexBin, "mcp", "list", "--json").Output()
	if err != nil {
		result.err = fmt.Errorf("could not inspect Codex registration: %w", err)
		return result
	}
	var servers []struct {
		Name      string `json:"name"`
		Enabled   *bool  `json:"enabled"`
		Transport struct {
			Type    string   `json:"type"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
			URL     string   `json:"url"`
		} `json:"transport"`
	}
	trimmed := bytes.TrimSpace(listOut)
	if len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(trimmed, &servers) != nil {
		result.err = fmt.Errorf("unrecognized Codex server list; configuration was not changed")
		return result
	}
	seen := make(map[string]bool, len(servers))
	for _, server := range servers {
		validTransport := server.Transport.Type == "stdio" && server.Transport.Command != "" ||
			server.Transport.Type == "streamable_http" && server.Transport.URL != ""
		if strings.TrimSpace(server.Name) == "" || seen[server.Name] || server.Enabled == nil || !validTransport {
			result.err = fmt.Errorf("unrecognized Codex server record; configuration was not changed")
			return result
		}
		seen[server.Name] = true
	}
	for _, server := range servers {
		if server.Name != "ironrun" {
			continue
		}
		result.state = "needs inspection"
		result.next = "Inspect the existing registration with codex mcp get ironrun --json; it was preserved without changes."
		if server.Enabled != nil && *server.Enabled && server.Transport.Type == "stdio" &&
			server.Transport.Command == "ironrun" && len(server.Transport.Args) == 1 && server.Transport.Args[0] == "mcp" {
			result.state, result.next = "configuration recognized", ""
		}
		return result
	}
	if err := exec.Command(codexBin, "mcp", "add", "ironrun", "--", "ironrun", "mcp").Run(); err != nil {
		result.err = fmt.Errorf("could not add Codex registration: %w", err)
		result.next = "Run codex mcp add ironrun -- ironrun mcp after resolving the Codex error."
		return result
	}
	result.state, result.next = "configuration written", ""
	return result
}
