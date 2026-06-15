package mcp_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mcpBin is the path to the compiled ironrun binary, built once in TestMain.
var mcpBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ironrun-mcp-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	mcpBin = filepath.Join(dir, "ironrun")
	build := exec.Command("go", "build", "-o", mcpBin, "./cmd/ironrun")
	build.Dir = ".." // repo root (mcp_test runs with wd = mcp/ dir)
	if out, berr := build.CombinedOutput(); berr != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", berr, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// passthroughPolicy returns a minimal passthrough policy YAML with an echo command.
const passthroughPolicy = `version: "1"
provider: passthrough
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`

// writeTempPolicy writes content to a temp file and returns its path.
func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "ironrun-policy-*.yml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatalf("write temp policy: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

// mcpProc manages a running ironrun mcp subprocess.
type mcpProc struct {
	cmd   *exec.Cmd
	stdin interface{ Write([]byte) (int, error) }
	lines chan string
}

// startMCP launches `ironrun mcp --policy <policyFile>` and returns a handle.
func startMCP(t *testing.T, policyFile string) *mcpProc {
	t.Helper()
	cmd := exec.Command(mcpBin, "mcp", "--policy", policyFile)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = os.Stderr // show server logs for debugging

	if err := cmd.Start(); err != nil {
		t.Fatalf("Start MCP server: %v", err)
	}

	p := &mcpProc{
		cmd:   cmd,
		stdin: stdinPipe,
		lines: make(chan string, 64),
	}

	// Background goroutine: feed stdout lines into the channel.
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				p.lines <- line
			}
		}
		close(p.lines)
	}()

	t.Cleanup(func() {
		stdinPipe.Close()
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	return p
}

// send marshals v as JSON and writes it as a newline-terminated message to stdin.
func (p *mcpProc) send(t *testing.T, v interface{}) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal send: %v", err)
	}
	if _, err := fmt.Fprintf(p.stdin, "%s\n", b); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
}

// readResponse reads lines from the server until it gets a JSON-RPC response
// (not a notification). Times out after the given duration.
func (p *mcpProc) readResponse(t *testing.T, timeout time.Duration) map[string]interface{} {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				t.Fatal("MCP server closed stdout unexpectedly")
			}
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Logf("skipping non-JSON line: %s", line)
				continue
			}
			// Skip pure notifications: have "method" but no "id".
			if _, hasMethod := m["method"]; hasMethod {
				if _, hasID := m["id"]; !hasID {
					continue
				}
			}
			return m
		case <-deadline:
			t.Fatalf("timeout (%s) waiting for MCP response", timeout)
			return nil
		}
	}
}

// initialize performs the MCP handshake and returns the initialize response.
func (p *mcpProc) initialize(t *testing.T) map[string]interface{} {
	t.Helper()
	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
		},
	})
	resp := p.readResponse(t, 5*time.Second)
	// Send the initialized notification (no response expected).
	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	return resp
}

// extractToolText digs out the text and isError flag from a tools/call response.
func extractToolText(t *testing.T, resp map[string]interface{}) (text string, isError bool) {
	t.Helper()
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("response has no 'result' field: %v", resp)
	}
	if v, ok := result["isError"].(bool); ok {
		isError = v
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatalf("result has no 'content' array: %v", result)
	}
	item, ok := content[0].(map[string]interface{})
	if !ok {
		t.Fatalf("content[0] is not an object: %v", content[0])
	}
	text, _ = item["text"].(string)
	return text, isError
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMCP_Initialize(t *testing.T) {
	policy := writeTempPolicy(t, passthroughPolicy)
	p := startMCP(t, policy)

	resp := p.initialize(t)

	if resp["error"] != nil {
		t.Fatalf("initialize returned error: %v", resp["error"])
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("no result in initialize response: %v", resp)
	}
	if result["serverInfo"] == nil {
		t.Errorf("expected serverInfo in initialize result, got: %v", result)
	}
	if result["protocolVersion"] == nil {
		t.Errorf("expected protocolVersion in initialize result, got: %v", result)
	}
}

func TestMCP_ListTools(t *testing.T) {
	policy := writeTempPolicy(t, passthroughPolicy)
	p := startMCP(t, policy)
	p.initialize(t)

	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	resp := p.readResponse(t, 5*time.Second)

	if resp["error"] != nil {
		t.Fatalf("tools/list returned error: %v", resp["error"])
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("no result in tools/list response: %v", resp)
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("no tools array in result: %v", result)
	}

	toolNames := make([]string, 0, len(tools))
	for _, tool := range tools {
		tm, ok := tool.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := tm["name"].(string); ok {
			toolNames = append(toolNames, name)
		}
	}

	wantTools := []string{"run_sealed", "list_commands", "validate_policy"}
	for _, want := range wantTools {
		found := false
		for _, got := range toolNames {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected tool %q, got tools: %v", want, toolNames)
		}
	}
}

func TestMCP_RunSealed_Passthrough(t *testing.T) {
	policy := writeTempPolicy(t, passthroughPolicy)
	p := startMCP(t, policy)
	p.initialize(t)

	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "run_sealed",
			"arguments": map[string]interface{}{
				"command_id": "greet",
			},
		},
	})
	resp := p.readResponse(t, 10*time.Second)

	text, isError := extractToolText(t, resp)
	if isError {
		t.Fatalf("run_sealed returned isError=true: %s", text)
	}
	if !strings.Contains(text, "exit_code: 0") {
		t.Errorf("expected exit_code: 0 in output, got:\n%s", text)
	}
	if !strings.Contains(text, "hello") {
		t.Errorf("expected 'hello' in output, got:\n%s", text)
	}
}

func TestMCP_ListCommands(t *testing.T) {
	policy := writeTempPolicy(t, passthroughPolicy)
	p := startMCP(t, policy)
	p.initialize(t)

	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "list_commands",
			"arguments": map[string]interface{}{},
		},
	})
	resp := p.readResponse(t, 5*time.Second)

	text, isError := extractToolText(t, resp)
	if isError {
		t.Fatalf("list_commands returned isError=true: %s", text)
	}
	if !strings.Contains(text, "greet") {
		t.Errorf("expected 'greet' command in list_commands output, got:\n%s", text)
	}
}

func TestMCP_UnknownCommand(t *testing.T) {
	policy := writeTempPolicy(t, passthroughPolicy)
	p := startMCP(t, policy)
	p.initialize(t)

	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "run_sealed",
			"arguments": map[string]interface{}{
				"command_id": "nonexistent-command-xyz",
			},
		},
	})
	resp := p.readResponse(t, 5*time.Second)

	text, isError := extractToolText(t, resp)
	if !isError {
		t.Errorf("expected isError=true for unknown command, got text:\n%s", text)
	}
	if !strings.Contains(text, "not found") {
		t.Errorf("expected 'not found' in error text, got:\n%s", text)
	}
}
