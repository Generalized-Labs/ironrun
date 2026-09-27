package main

import (
	"strings"
	"testing"
)

const zero40 = "0000000000000000000000000000000000000000"

func TestPushRange(t *testing.T) {
	// Branch deletion (zero LOCAL sha): nothing to scan — refuse loudly
	// rather than scanning garbage.
	if _, err := pushRange("refs/heads/old", zero40, "abc123"); err == nil {
		t.Fatal("pushRange accepted a branch deletion (zero local sha)")
	}
	// New branch (zero REMOTE sha): highest-risk push, must be scanned via
	// the new-branch heuristic — never skipped.
	args, err := pushRange("refs/heads/new", "def456", zero40)
	if err != nil {
		t.Fatalf("pushRange refused a new branch: %v", err)
	}
	if len(args) != 1 || !strings.Contains(args[0], "def456") {
		t.Fatalf("new branch did not get the new-branch scan range: %v", args)
	}
	// Normal update: old..new.
	args, err = pushRange("refs/heads/main", "def456", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 || args[0] != "abc123..def456" {
		t.Fatalf("wrong range for branch update: %v", args)
	}
}

func TestIsZeroSha(t *testing.T) {
	if !isZeroSha(zero40) {
		t.Fatal("all-zero sha not recognized")
	}
	if !isZeroSha("0000") {
		t.Fatal("short all-zero sha not recognized")
	}
	if isZeroSha("abc123") || isZeroSha("") {
		t.Fatal("false positive on non-zero/empty sha")
	}
}
