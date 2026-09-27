package runner

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/sealedexec"
)

// clearCIEnv removes every CI marker checkCITrust reads, so table tests start
// from a clean slate regardless of the ambient environment.
func clearCIEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_HEAD_REPOSITORY", "GITHUB_REPOSITORY",
		"GITLAB_CI", "CI_PIPELINE_SOURCE", "CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "CI_MERGE_REQUEST_PROJECT_ID",
		"CIRCLECI", "CIRCLE_PR_NUMBER", "CIRCLE_PR_USERNAME",
		"JENKINS_URL", "JENKINS_HOME", "CHANGE_ID", "CHANGE_FORK",
		"IRONRUN_ALLOW_PRT",
	} {
		t.Setenv(k, "")
	}
}

func TestIsDangerousEnv_NewInjectorPrefixes(t *testing.T) {
	dangerous := []string{
		"LD_AUDIT",
		"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONBREAKPOINT",
		"NODE_OPTIONS",
		"RUBYOPT", "RUBYLIB",
		"PERL5OPT", "PERL5LIB",
		"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
		"ZDOTDIR",
		"GIT_SSH", "GIT_SSH_COMMAND",
		// pre-existing entries still hold
		"LD_PRELOAD", "BASH_ENV", "DYLD_INSERT_LIBRARIES",
	}
	for _, k := range dangerous {
		if !isDangerousEnv(k) {
			t.Errorf("expected %q to be treated as dangerous", k)
		}
	}
	safe := []string{"PATH", "HOME", "EDITOR", "MYAPP_TOKEN", "LANG"}
	for _, k := range safe {
		if isDangerousEnv(k) {
			t.Errorf("expected %q to be treated as safe", k)
		}
	}
}

func TestBuildEnv_StripsInjectorVars(t *testing.T) {
	injected := map[string]string{
		"LD_AUDIT": "/tmp/evil.so", "PYTHONPATH": "/tmp/evil", "PYTHONSTARTUP": "/tmp/evil.py",
		"NODE_OPTIONS": "--require /tmp/evil.js", "RUBYOPT": "-r/tmp/evil",
		"RUBYLIB": "/tmp/evil", "PERL5OPT": "-M/tmp/evil", "PERL5LIB": "/tmp/evil",
		"JAVA_TOOL_OPTIONS": "-agentpath:/tmp/evil.so", "JDK_JAVA_OPTIONS": "-javaagent:/tmp/evil.jar",
		"_JAVA_OPTIONS": "-agentpath:/tmp/evil.so", "ZDOTDIR": "/tmp/evil",
		"GIT_SSH_COMMAND": "/tmp/evil-ssh",
	}
	for k, v := range injected {
		t.Setenv(k, v)
	}
	env := buildEnv(nil, nil)
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		if _, bad := injected[key]; bad {
			t.Errorf("dangerous var %q survived buildEnv", key)
		}
	}
}

func TestBuildEnv_PolicySecretsAreOperatorIntent(t *testing.T) {
	// Vars declared via policy/options are the operator's explicit intent and
	// must NOT be stripped — only ambient inheritance is scrubbed.
	env := buildEnv(nil, map[string]string{"PYTHONPATH": "operator-value"})
	found := false
	for _, e := range env {
		if e == "PYTHONPATH=operator-value" {
			found = true
		}
	}
	if !found {
		t.Error("policy-provided secret was stripped from the child env")
	}
}

func TestCheckCITrust_GitLab(t *testing.T) {
	t.Run("fork merge request denied", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("GITLAB_CI", "true")
		t.Setenv("CI_PIPELINE_SOURCE", "merge_request_event")
		t.Setenv("CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "111")
		t.Setenv("CI_MERGE_REQUEST_PROJECT_ID", "222")
		if err := checkCITrust(false); err == nil {
			t.Error("expected fork MR to be denied")
		}
	})
	t.Run("same-project merge request allowed", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("GITLAB_CI", "true")
		t.Setenv("CI_PIPELINE_SOURCE", "merge_request_event")
		t.Setenv("CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "222")
		t.Setenv("CI_MERGE_REQUEST_PROJECT_ID", "222")
		if err := checkCITrust(false); err != nil {
			t.Errorf("expected same-project MR to be allowed, got %v", err)
		}
	})
	t.Run("merge request with unverifiable fork status denied", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("GITLAB_CI", "true")
		t.Setenv("CI_PIPELINE_SOURCE", "merge_request_event")
		if err := checkCITrust(false); err == nil {
			t.Error("expected MR with unknown fork status to be denied (fail closed)")
		}
	})
	t.Run("push pipeline allowed", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("GITLAB_CI", "true")
		t.Setenv("CI_PIPELINE_SOURCE", "push")
		if err := checkCITrust(false); err != nil {
			t.Errorf("expected push pipeline to be allowed, got %v", err)
		}
	})
}

func TestCheckCITrust_CircleCI(t *testing.T) {
	t.Run("fork PR build denied", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("CIRCLECI", "true")
		t.Setenv("CIRCLE_PR_NUMBER", "42")
		t.Setenv("CIRCLE_PR_USERNAME", "attacker")
		if err := checkCITrust(false); err == nil {
			t.Error("expected CircleCI fork PR build to be denied")
		}
	})
	t.Run("non-PR build allowed", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("CIRCLECI", "true")
		if err := checkCITrust(false); err != nil {
			t.Errorf("expected plain CircleCI build to be allowed, got %v", err)
		}
	})
}

func TestCheckCITrust_Jenkins(t *testing.T) {
	t.Run("fork change build denied", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("JENKINS_URL", "https://jenkins.example.com/")
		t.Setenv("CHANGE_ID", "7")
		t.Setenv("CHANGE_FORK", "attacker/repo")
		if err := checkCITrust(false); err == nil {
			t.Error("expected Jenkins fork change build to be denied")
		}
	})
	t.Run("change build with unknown fork status denied", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("JENKINS_HOME", "/var/jenkins")
		t.Setenv("CHANGE_ID", "7")
		if err := checkCITrust(false); err == nil {
			t.Error("expected Jenkins change build with unknown fork status to be denied (fail closed)")
		}
	})
	t.Run("branch build allowed", func(t *testing.T) {
		clearCIEnv(t)
		t.Setenv("JENKINS_URL", "https://jenkins.example.com/")
		if err := checkCITrust(false); err != nil {
			t.Errorf("expected Jenkins branch build to be allowed, got %v", err)
		}
	})
}

func TestCheckCITrust_PullRequestTargetEnvKillSwitchIgnored(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")
	// The legacy env form must NOT grant access anymore.
	t.Setenv("IRONRUN_ALLOW_PRT", "1")
	if err := checkCITrust(false); err == nil {
		t.Error("expected IRONRUN_ALLOW_PRT=1 to be ignored (env kill-switch is dead)")
	}
	// The operator flag form grants access.
	if err := checkCITrust(true); err != nil {
		t.Errorf("expected allowPullRequestTarget=true to permit, got %v", err)
	}
}

func TestArmSealedExec_StripsInheritedSentinels(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("shim rewrite is Linux-only")
	}
	newCmd := func() *exec.Cmd {
		c := exec.Command("/bin/true")
		c.Env = []string{"A=B", sealedexec.EnvNoSeal + "=1", sealedexec.EnvSkipSeccomp + "=1"}
		return c
	}
	has := func(env []string, kv string) bool {
		for _, e := range env {
			if e == kv {
				return true
			}
		}
		return false
	}
	count := func(env []string, kv string) int {
		n := 0
		for _, e := range env {
			if e == kv {
				n++
			}
		}
		return n
	}

	// Default: seal on, seccomp on. Inherited sentinels stripped, none re-added.
	c := newCmd()
	ok, err := armSealedExec(c, false, true)
	if err != nil || !ok {
		t.Fatalf("armSealedExec = (%v, %v), want (true, nil)", ok, err)
	}
	for _, e := range c.Env {
		if strings.HasPrefix(e, sealedexec.EnvNoSeal+"=") || strings.HasPrefix(e, sealedexec.EnvSkipSeccomp+"=") {
			t.Errorf("inherited sentinel survived the shim rewrite: %q", e)
		}
	}
	if !has(c.Env, sealedexec.EnvSentinel+"=1") {
		t.Errorf("expected %s=1 in shim env", sealedexec.EnvSentinel)
	}

	// Operator --no-seal: exactly one IRONRUN_NO_SEAL=1 (the inherited one was
	// stripped, the operator one added).
	c = newCmd()
	ok, err = armSealedExec(c, true, true)
	if err != nil || !ok {
		t.Fatalf("armSealedExec = (%v, %v), want (true, nil)", ok, err)
	}
	if n := count(c.Env, sealedexec.EnvNoSeal+"=1"); n != 1 {
		t.Errorf("expected exactly one %s=1 with noSeal=true, got %d", sealedexec.EnvNoSeal, n)
	}

	// Seal-only mode (seccomp not requested): skip marker added exactly once.
	c = newCmd()
	ok, err = armSealedExec(c, false, false)
	if err != nil || !ok {
		t.Fatalf("armSealedExec = (%v, %v), want (true, nil)", ok, err)
	}
	if n := count(c.Env, sealedexec.EnvSkipSeccomp+"=1"); n != 1 {
		t.Errorf("expected exactly one %s=1 in seal-only mode, got %d", sealedexec.EnvSkipSeccomp, n)
	}
	if has(c.Env, sealedexec.EnvNoSeal+"=1") {
		t.Errorf("unexpected %s=1 in seal-only mode", sealedexec.EnvNoSeal)
	}
}
