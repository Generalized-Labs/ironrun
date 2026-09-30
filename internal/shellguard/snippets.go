// Package shellguard owns shell-side leak prevention: idempotent rc
// snippets that warn when a user types `export NAME=<literal>` for a vault
// alias or a secret-shaped name, and exact-value purging of shell history
// files.
//
// Design note, stated loudly: the guard WARNS, it does not block. No
// portable shell hook (bash DEBUG trap, zsh preexec, fish fish_preexec) can
// cancel the command about to run, and silently stripping the value would be
// worse than warning. The warning fires before the command executes, so the
// user can Ctrl-C.
package shellguard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Shell identifies a supported shell.
type Shell int

const (
	Bash Shell = iota
	Zsh
	Fish
)

// ParseShell maps a name to a Shell.
func ParseShell(name string) (Shell, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "sh":
		return Bash, nil
	case "zsh":
		return Zsh, nil
	case "fish":
		return Fish, nil
	}
	return Bash, fmt.Errorf("unsupported shell %q (bash, zsh, fish)", name)
}

// DetectShell guesses the shell from $SHELL.
func DetectShell() Shell {
	base := filepath.Base(os.Getenv("SHELL"))
	s, err := ParseShell(base)
	if err != nil {
		return Bash
	}
	return s
}

// DefaultRCPath is where Install appends the snippet for a shell.
func DefaultRCPath(s Shell) string {
	home, _ := os.UserHomeDir()
	switch s {
	case Zsh:
		return filepath.Join(home, ".zshrc")
	case Fish:
		return filepath.Join(home, ".config", "fish", "config.fish")
	default:
		return filepath.Join(home, ".bashrc")
	}
}

// BeginMarker/EndMarker wrap the managed snippet block; Install is
// idempotent by checking for BeginMarker.
const BeginMarker = "# >>> ironrun shell-guard >>>"
const EndMarker = "# <<< ironrun shell-guard <<<"

var safeAlias = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// cleanAliases keeps env-var-safe aliases (plus their upper-case form, since
// users export both FOO and foo). Anything else stays covered by the generic
// name patterns.
func cleanAliases(aliases []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range aliases {
		for _, v := range []string{a, strings.ToUpper(a)} {
			if !safeAlias.MatchString(v) || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// Snippet returns the idempotent rc snippet for the shell, embedding the
// given vault aliases into the guard.
func Snippet(s Shell, aliases []string) string {
	switch s {
	case Zsh:
		return zshSnippet(aliases)
	case Fish:
		return fishSnippet(aliases)
	default:
		return bashSnippet(aliases)
	}
}

func header() string {
	return BeginMarker + "\n" +
		"# Installed by `ironrun shell init`. Warns LOUDLY when a command line looks like\n" +
		"# `export NAME=<literal>` where NAME is a vault alias or a secret-shaped name\n" +
		"# (SECRET/TOKEN/KEY/PASSWORD/CREDENTIAL): the value would land in shell history.\n" +
		"# This guard warns — it cannot portably stop the command. Press Ctrl-C on sight.\n"
}

func footer() string { return EndMarker + "\n" }

func bashSnippet(aliases []string) string {
	cases := append([]string{"*SECRET*", "*TOKEN*", "*KEY*", "*PASSWORD*", "*CREDENTIAL*"}, cleanAliases(aliases)...)
	return header() +
		"export HISTCONTROL=ignoreboth\n" +
		"_ironrun_export_guard() {\n" +
		"    local line=\"$1\" name val\n" +
		"    case \"$line\" in\n" +
		"        export\\ [A-Za-z_]*=*)\n" +
		"            name=\"${line#export }\"\n" +
		"            name=\"${name%%=*}\"\n" +
		"            case \"$name\" in\n" +
		"                " + strings.Join(cases, "|") + ")\n" +
		"                    val=\"${line#*=}\"\n" +
		"                    if [ \"${#val}\" -ge 8 ]; then\n" +
		"                        printf '\\n\\033[1;31m[ironrun] `export %s=<value>` is about to run — the literal value WILL be written to your shell history file.\\033[0m\\n' \"$name\" >&2\n" +
		"                        printf '[ironrun] Use `ironrun run` to inject secrets instead. Press Ctrl-C now to abort.\\n\\n' >&2\n" +
		"                    fi\n" +
		"                    ;;\n" +
		"            esac\n" +
		"            ;;\n" +
		"    esac\n" +
		"}\n" +
		"_ironrun_preexec_dispatch() { _ironrun_export_guard \"$BASH_COMMAND\"; }\n" +
		"trap '_ironrun_preexec_dispatch' DEBUG\n" +
		footer()
}

func zshSnippet(aliases []string) string {
	cases := append([]string{"*SECRET*", "*TOKEN*", "*KEY*", "*PASSWORD*", "*CREDENTIAL*"}, cleanAliases(aliases)...)
	return header() +
		"setopt HIST_IGNORE_SPACE\n" +
		"_ironrun_export_guard() {\n" +
		"    local line=\"$1\" name val\n" +
		"    case \"$line\" in\n" +
		"        export\\ [A-Za-z_]*=*)\n" +
		"            name=\"${line#export }\"\n" +
		"            name=\"${name%%=*}\"\n" +
		"            case \"$name\" in\n" +
		"                " + strings.Join(cases, "|") + ")\n" +
		"                    val=\"${line#*=}\"\n" +
		"                    if (( ${#val} >= 8 )); then\n" +
		"                        print -P \"\"\n" +
		"                        print -P \"%F{red}%B[ironrun]%b \\`export $name=<value>\\` is about to run — the literal value WILL land in your shell history file.%f\"\n" +
		"                        print -P \"[ironrun] Use \\`ironrun run\\` to inject secrets instead. Press Ctrl-C now to abort.\"\n" +
		"                        print -P \"\"\n" +
		"                    fi\n" +
		"                    ;;\n" +
		"            esac\n" +
		"            ;;\n" +
		"    esac\n" +
		"}\n" +
		"autoload -Uz add-zsh-hook 2>/dev/null && add-zsh-hook preexec _ironrun_export_guard\n" +
		footer()
}

func fishSnippet(aliases []string) string {
	alts := []string{"SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIAL"}
	exact := cleanAliases(aliases)
	nameRe := strings.Join(alts, "|")
	if len(exact) > 0 {
		nameRe += "|^(" + strings.Join(exact, "|") + ")$"
	}
	return header() +
		"function __ironrun_export_guard --on-event fish_preexec\n" +
		"    set -l line $argv[1]\n" +
		"    if string match -qr '^export\\s+[A-Za-z_][A-Za-z0-9_]*=' -- $line\n" +
		"        set -l name (string replace -r '^export\\s+([A-Za-z_][A-Za-z0-9_]*)=.*$' '$1' -- $line)\n" +
		"        set -l val (string replace -r '^export\\s+[A-Za-z_][A-Za-z0-9_]*=' '' -- $line)\n" +
		"        if string match -qr '" + nameRe + "' -- $name; and test (string length -- $val) -ge 8\n" +
		"            set_color --bold red\n" +
		"            echo \"\"\n" +
		"            echo \"[ironrun] `export $name=<value>` is about to run — the literal value WILL land in your fish history file.\"\n" +
		"            echo \"[ironrun] Use `ironrun run` to inject secrets instead. Press Ctrl-C now to abort.\"\n" +
		"            echo \"\"\n" +
		"            set_color normal\n" +
		"        end\n" +
		"    end\n" +
		"end\n" +
		footer()
}

// Install appends the snippet to rcPath unless the marker block is already
// present. It returns true when it wrote something.
func Install(rcPath, snippet string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(rcPath), 0o755); err != nil {
		return false, err
	}
	var existing string
	if data, err := os.ReadFile(rcPath); err == nil {
		existing = string(data)
		if strings.Contains(existing, BeginMarker) {
			return false, nil // already installed: idempotent no-op
		}
	}
	var sb strings.Builder
	sb.WriteString(existing)
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		sb.WriteString("\n")
	}
	if existing != "" {
		sb.WriteString("\n")
	}
	sb.WriteString(snippet)
	// Atomic write: a crash mid-write must never truncate the user's rc
	// file. Preserve the existing file's mode when there is one.
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(rcPath); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := atomicWrite(rcPath, []byte(sb.String()), mode); err != nil {
		return false, fmt.Errorf("write %s: %w", rcPath, err)
	}
	return true, nil
}
