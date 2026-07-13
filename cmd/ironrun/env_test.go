package main

import (
	"os"
	"strings"
	"testing"
)

func TestAttachPolicyToActiveEnvironment(t *testing.T) {
	path := t.TempDir() + "/ironrun.yml"
	data := "version: \"1\"\nprovider: env\ncommands: []\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := attachPolicyToActiveEnvironment(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "environment_set: active") {
		t.Fatalf("missing environment_set: %s", first)
	}
	if err := attachPolicyToActiveEnvironment(path); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if strings.Count(string(second), "environment_set:") != 1 {
		t.Fatalf("duplicate environment_set: %s", second)
	}
}
