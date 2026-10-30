// workspaceprobe supplies a synthetic native-store adapter and a real loopback
// HTTP child for the Linux MCP integration test. It never contacts a remote host.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	if os.Args[1] == "http" {
		probeHTTP()
		return
	}
	// The native adapter stores only the synthetic project root key. Actual
	// environment entries continue through Ironrun's encrypted vault.
	if len(os.Args) < 8 {
		os.Exit(2)
	}
	attributes := os.Args[len(os.Args)-6:]
	if attributes[0] != "service" || attributes[1] != "ironrun" || attributes[2] != "scope" || attributes[4] != "key" {
		os.Exit(2)
	}
	digest := sha256.Sum256([]byte(strings.Join(attributes, "\x00")))
	path := filepath.Join(os.Getenv("IRONRUN_TEST_NATIVE_STORE_DIR"), hex.EncodeToString(digest[:]))
	switch os.Args[1] {
	case "store":
		value, err := io.ReadAll(os.Stdin)
		if err != nil || os.WriteFile(path, []byte(strings.TrimSuffix(string(value), "\n")), 0600) != nil {
			os.Exit(1)
		}
	case "lookup":
		value, err := os.ReadFile(path)
		if err != nil {
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(value)
	case "clear":
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
}

func probeHTTP() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	fmt.Println("PROBE_STARTED")
	value := os.Getenv("IRONRUN_E2E_TOKEN")
	fmt.Println("credential=" + value)
	req, err := http.NewRequest(http.MethodGet, os.Args[2], nil)
	if err != nil {
		os.Exit(2)
	}
	req.Header.Set("X-Ironrun-Fixture", value)
	// An explicit transport avoids ambient proxies; the test supplies only a
	// 127.0.0.1 URL, so all observed traffic remains local.
	client := &http.Client{Transport: &http.Transport{}, Timeout: 2 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println("DIAL_BLOCKED")
		os.Exit(1)
	}
	defer response.Body.Close()
	if _, err := io.Copy(os.Stdout, response.Body); err != nil {
		os.Exit(1)
	}
	fmt.Println("DIAL_OK")
}
