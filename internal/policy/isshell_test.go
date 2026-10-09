package policy

import "testing"

func TestIsShellString_PathAndNameVariants(t *testing.T) {
	shell := [][]string{
		{"sh", "-c", "x"},
		{"/bin/sh"},
		{"/bin//sh", "-c", "x"},    // doubled separator
		{"/bin/./sh"},              // unnormalized path
		{"/private/bin/sh"},        // unusual directory
		{"/opt/homebrew/bin/bash"}, // homebrew path not in the old allowlist
		{"/usr/bin/csh"}, {"/usr/bin/tcsh"},
		{"mksh"}, {"busybox"}, {"/bin/busybox"},
		{"env", "sh", "-c", "x"},         // env wrapper
		{"env", "-i", "FOO=bar", "bash"}, // env with flag + assignment
		{"/usr/bin/env", "zsh"},
	}
	for _, argv := range shell {
		if !IsShellString(argv) {
			t.Errorf("expected %v to be detected as a shell", argv)
		}
	}

	notShell := [][]string{
		{"npm", "test"},
		{"python", "-c", "print(1)"},
		{"/usr/bin/make", "build"},
		{"env", "FOO=bar", "python"}, // env wrapping a non-shell
		{"envsubst"},                 // name merely starts with "env"
		{"go", "test", "./..."},
	}
	for _, argv := range notShell {
		if IsShellString(argv) {
			t.Errorf("did not expect %v to be detected as a shell", argv)
		}
	}
}
