package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/envset"
)

// runDoctor runs `ironrun doctor` in dir and returns output and the exit code.
func runDoctor(t *testing.T, dir string) (string, int) {
	t.Helper()
	bin := buildBinary(t)
	cmd := exec.Command(bin, "doctor")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running doctor: %v\noutput: %s", err, out)
	}
	return string(out), code
}

func writePolicy(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ironrun.yml"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestDoctor_AllPass: a valid env-provider policy whose binary resolves passes
// every check and exits 0.
func TestDoctor_AllPass(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `version: "1"
provider: env
commands:
  - id: ver
    argv: [go, version]
`)
	out, code := runDoctor(t, dir)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	for _, want := range []string{"valid", "redaction self-test passed", "All checks passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q\noutput:\n%s", want, out)
		}
	}
}

// TestDoctor_MissingBinary: a command whose binary is absent fails with a
// non-zero exit and a clear message.
func TestDoctor_MissingBinary(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `version: "1"
provider: env
commands:
  - id: nope
    argv: [definitely-not-a-real-binary-xyz]
`)
	out, code := runDoctor(t, dir)
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing binary\noutput:\n%s", out)
	}
	if !strings.Contains(out, "not found on PATH") {
		t.Errorf("expected 'not found on PATH'\noutput:\n%s", out)
	}
}

// TestDoctor_NoPolicy: with no policy file, doctor fails and points at init.
func TestDoctor_NoPolicy(t *testing.T) {
	dir := t.TempDir()
	out, code := runDoctor(t, dir)
	if code == 0 {
		t.Fatalf("expected non-zero exit when policy is missing\noutput:\n%s", out)
	}
	if !strings.Contains(out, "ironrun init") {
		t.Errorf("expected init hint in output\noutput:\n%s", out)
	}
}

// TestDoctor_ShellCommandWarned: a shell-string command is flagged (denied at
// runtime) rather than passed.
func TestDoctor_ShellCommandWarned(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `version: "1"
provider: env
commands:
  - id: sh
    argv: [sh, -c, "echo hi"]
`)
	out, _ := runDoctor(t, dir)
	if !strings.Contains(out, "shell invocation") {
		t.Errorf("expected shell command to be flagged\noutput:\n%s", out)
	}
}

func doctorEntryPolicy(t *testing.T, dir string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	writePolicy(t, dir, fmt.Sprintf(`version: "2"
environment_set: active
commands:
  - id: test
    argv: [%q]
    secrets: [DATABASE_URL, API_TOKEN]
`, binary))
}

func doctorMetadata(t *testing.T, dir string) envset.Metadata {
	t.Helper()
	identity, err := envset.DiscoverIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	return envset.Metadata{Version: 2, Identity: identity, Active: "dev", Sets: map[string]envset.Set{
		"dev": {Name: "dev", Entries: []envset.Entry{
			{Name: "DATABASE_URL", Kind: envset.EntryEnvironment, Target: "DATABASE_URL"},
			{Name: "API_TOKEN", Kind: envset.EntryEnvironment, Target: "API_TOKEN"},
		}},
	}}
}

func writeDoctorMetadata(t *testing.T, dir string, metadata envset.Metadata) {
	t.Helper()
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".ironrun"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".ironrun", "environments.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// Removing the local-environment preflight must restore the original false
// green: every case below then exits zero despite unusable configuration.
func TestDoctor_LocalEnvironmentBlockers(t *testing.T) {
	cases := []struct {
		name   string
		change func(*envset.Metadata)
		want   []string
	}{
		{"missing metadata", nil, []string{"environment metadata is missing", "ironrun env init dev"}},
		{"no active set", func(m *envset.Metadata) { m.Active = "" }, []string{"no active environment", "ironrun env use dev"}},
		{"missing selected set", func(m *envset.Metadata) { m.Active = "staging" }, []string{`environment "staging" is missing`, "ironrun env use dev"}},
		{"expired set", func(m *envset.Metadata) {
			expired := time.Now().Add(-time.Hour)
			m.Sets["session"] = envset.Set{Name: "session", Temporary: true, ExpiresAt: &expired}
			m.Active = "session"
		}, []string{`environment "session" has expired`, "ironrun env use dev"}},
		{"identity mismatch", func(m *envset.Metadata) { m.Identity.CanonicalPath += "-different-checkout" }, []string{"project identity changed", "recorded checkout path and Git origin"}},
		{"inconsistent selected name", func(m *envset.Metadata) {
			set := m.Sets["dev"]
			set.Name = "other"
			m.Sets["dev"] = set
		}, []string{"selected environment metadata is invalid"}},
		{"missing entries", func(m *envset.Metadata) { m.Sets["dev"] = envset.Set{Name: "dev"} }, []string{
			`command "test": entry "API_TOKEN" is not configured in "dev"`, "ironrun env set dev API_TOKEN",
			`command "test": entry "DATABASE_URL" is not configured in "dev"`, "ironrun env set dev DATABASE_URL",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			doctorEntryPolicy(t, dir)
			if tc.change != nil {
				metadata := doctorMetadata(t, dir)
				tc.change(&metadata)
				writeDoctorMetadata(t, dir, metadata)
			}
			before := doctorFileSnapshot(t, dir)
			out, code := runDoctor(t, dir)
			if code == 0 {
				t.Errorf("doctor accepted unusable local environment:\n%s", out)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("missing diagnostic %q:\n%s", want, out)
				}
			}
			if tc.name == "missing entries" && strings.Index(out, `entry "API_TOKEN"`) > strings.Index(out, `entry "DATABASE_URL"`) {
				t.Errorf("missing entries are not sorted:\n%s", out)
			}
			if after := doctorFileSnapshot(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("doctor changed project files: before=%v after=%v", before, after)
			}
		})
	}
}

func TestDoctor_LocalMetadataChecksDoNotOpenVault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native-store trap uses POSIX scripts")
	}
	dir := t.TempDir()
	doctorEntryPolicy(t, dir)
	metadata := doctorMetadata(t, dir)
	// Version-one metadata must be understood without writing a migration.
	metadata.Version = 1
	metadata.Sets["dev"] = envset.Set{Name: "dev", Keys: []string{"DATABASE_URL", "API_TOKEN"}}
	writeDoctorMetadata(t, dir, metadata)
	trapDir := t.TempDir()
	marker := filepath.Join(trapDir, "native-store-was-called")
	for _, binary := range []string{"secret-tool", "security"} {
		body := fmt.Sprintf("#!/bin/sh\n: > '%s'\nexit 1\n", marker)
		if err := os.WriteFile(filepath.Join(trapDir, binary), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", trapDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	before := doctorFileSnapshot(t, dir)
	out, code := runDoctor(t, dir)
	if code != 0 {
		t.Fatalf("configured metadata should pass without a vault: exit=%d\n%s", code, out)
	}
	for _, want := range []string{`selected environment "dev"`, `command "test": required entry names are configured`, "Secret values and vault access were not checked"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing metadata-only diagnostic %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("doctor invoked the native credential manager")
	}
	if after := doctorFileSnapshot(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("doctor changed project files: before=%v after=%v", before, after)
	}
}

func TestDoctor_V1ActiveEnvironmentMapsAliasesToEntryNames(t *testing.T) {
	for _, kind := range []string{"env", "file"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			writePolicy(t, dir, fmt.Sprintf(`version: "1"
environment_set: active
secrets:
  database:
    env: DATABASE_URL
    store: envfile
    allow: [test]
    kind: %s
    filename: credentials.json
commands:
  - id: test
    argv: [%q]
    secrets: [database]
`, kind, binary))
			metadata := doctorMetadata(t, dir)
			metadata.Sets["dev"] = envset.Set{Name: "dev"}
			writeDoctorMetadata(t, dir, metadata)
			out, code := runDoctor(t, dir)
			action := "set"
			if kind == "file" {
				action = "file"
			}
			if code == 0 || !strings.Contains(out, `entry "DATABASE_URL" is not configured`) || !strings.Contains(out, "ironrun env "+action+" dev DATABASE_URL") {
				t.Fatalf("v1 alias was not checked by its stored entry name: exit=%d\n%s", code, out)
			}
		})
	}
}

func TestDoctor_EnvironmentRecoveryNamesAreSafe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setName string
		want    string
	}{
		{"leading flag", "-dev", "ironrun env set -- -dev API_TOKEN"},
		{"terminal escape", "dev\x1b[2J", "selected environment metadata is invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			doctorEntryPolicy(t, dir)
			metadata := doctorMetadata(t, dir)
			metadata.Active = tc.setName
			metadata.Sets = map[string]envset.Set{tc.setName: {Name: tc.setName}}
			writeDoctorMetadata(t, dir, metadata)
			out, code := runDoctor(t, dir)
			if code == 0 || !strings.Contains(out, tc.want) || strings.ContainsRune(out, '\x1b') {
				t.Fatalf("unsafe recovery output: exit=%d\n%s", code, out)
			}
		})
	}
}

func TestDoctor_PaddedEnvironmentNames(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing=%t", missing), func(t *testing.T) {
			dir := t.TempDir()
			doctorEntryPolicy(t, dir)
			metadata := doctorMetadata(t, dir)
			set := metadata.Sets["dev"]
			set.Name = " dev " // The environment API preserves padding after validation.
			if missing {
				set.Entries = nil
			}
			metadata.Active = set.Name
			metadata.Sets = map[string]envset.Set{set.Name: set}
			writeDoctorMetadata(t, dir, metadata)
			before := doctorFileSnapshot(t, dir)
			out, code := runDoctor(t, dir)
			if missing {
				if code == 0 || !strings.Contains(out, "ironrun env set ' dev ' API_TOKEN") {
					t.Fatalf("padded environment repair lost argument boundaries: exit=%d\n%s", code, out)
				}
			} else if code != 0 || !strings.Contains(out, `selected environment " dev "`) {
				t.Fatalf("runtime-valid padded environment was rejected: exit=%d\n%s", code, out)
			}
			if after := doctorFileSnapshot(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatal("doctor changed padded-name metadata")
			}
		})
	}
}

func TestDoctor_NonprintingPaddingUsesManualRecovery(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing=%t", missing), func(t *testing.T) {
			dir := t.TempDir()
			doctorEntryPolicy(t, dir)
			metadata := doctorMetadata(t, dir)
			set := metadata.Sets["dev"]
			set.Name = "\ndev\n"
			if missing {
				set.Entries = nil
			}
			metadata.Active = set.Name
			metadata.Sets = map[string]envset.Set{set.Name: set}
			writeDoctorMetadata(t, dir, metadata)
			out, code := runDoctor(t, dir)
			if strings.Contains(out, set.Name) || strings.Contains(out, "metadata is invalid") {
				t.Fatalf("valid nonprinting padding was emitted literally or called invalid:\n%s", out)
			}
			if missing {
				if code == 0 || !strings.Contains(out, "configure this entry through environment management") {
					t.Fatalf("missing entry needs manual recovery: exit=%d\n%s", code, out)
				}
			} else if code != 0 {
				t.Fatalf("valid complete padded metadata should pass: exit=%d\n%s", code, out)
			}
		})
	}
}

func TestDoctor_LocalFileEntryChecksNamesOnly(t *testing.T) {
	dir := t.TempDir()
	doctorEntryPolicy(t, dir)
	metadata := doctorMetadata(t, dir)
	set := metadata.Sets["dev"]
	set.Entries[0] = envset.Entry{Name: "DATABASE_URL", Kind: envset.EntryFile, Target: "DATABASE_URL", Filename: "credentials.json"}
	metadata.Sets["dev"] = set
	writeDoctorMetadata(t, dir, metadata)
	before := doctorFileSnapshot(t, dir)
	out, code := runDoctor(t, dir)
	if code != 0 || !strings.Contains(out, "required entry names are configured") || !strings.Contains(out, "Secret values and vault access were not checked") {
		t.Fatalf("file entry metadata should pass without encrypted values: exit=%d\n%s", code, out)
	}
	if after := doctorFileSnapshot(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("file-entry inspection changed project files")
	}
}

func TestDoctor_LocalEnvironmentUsesExplicitPolicyDirectory(t *testing.T) {
	project := t.TempDir()
	doctorEntryPolicy(t, project)
	writeDoctorMetadata(t, project, doctorMetadata(t, project))
	cmd := exec.Command(buildBinary(t), "doctor", "--policy", filepath.Join(project, "ironrun.yml"))
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `selected environment "dev"`) {
		t.Fatalf("doctor did not inspect explicit policy directory: %v\n%s", err, out)
	}
}

func TestDoctor_V2WithoutEntryBindingsNeedsNoEnvironment(t *testing.T) {
	dir := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	writePolicy(t, dir, fmt.Sprintf("version: \"2\"\ncommands:\n  - id: health\n    argv: [%q]\n", binary))
	out, code := runDoctor(t, dir)
	if code != 0 || !strings.Contains(out, "no saved commands require environment entries") {
		t.Fatalf("health-only v2 policy should not require a vault: exit=%d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".ironrun")); !os.IsNotExist(err) {
		t.Fatal("doctor created local environment state")
	}
}

type doctorFileState struct {
	Mode    os.FileMode
	ModTime time.Time
	Data    string
}

func doctorFileSnapshot(t *testing.T, root string) map[string]doctorFileState {
	t.Helper()
	snapshot := map[string]doctorFileState{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		state := doctorFileState{Mode: info.Mode(), ModTime: info.ModTime()}
		if !info.IsDir() {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			state.Data = string(data)
		}
		snapshot[path] = state
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
