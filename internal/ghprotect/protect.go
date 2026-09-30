// Package ghprotect builds the `gh api` calls that harden a GitHub
// repository (or every repository in an org) against secret leaks:
//
//  1. Enable secret scanning + push protection (repo PATCH).
//  2. Set org defaults so new repositories inherit both (org PATCH).
//  3. Publish custom push-protection patterns for internal token shapes
//     (bulk POST to the repo's secret-scanning custom-patterns endpoint).
//
// Only verified public REST endpoints are used. Two things have no API and
// are therefore surfaced as explicit manual checklist items instead of
// invented calls: publishing a custom pattern (patterns land unpublished;
// only the creator can dry-run/publish, UI-only) and the standing bypass
// policy ("allow bypasses" / "require bypass reason" live in org settings).
package ghprotect

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Call is one `gh api` invocation.
type Call struct {
	Method string
	Path   string            // e.g. "repos/octo/hello"
	Fields map[string]string // rendered as -f 'a[b]=c'
	Body   any               // rendered as --input - JSON via heredoc
}

// Render prints the exact shell command the runner would execute.
func (c Call) Render() string {
	var sb strings.Builder
	sb.WriteString("gh api --method " + c.Method + " " + shellQuote(c.Path))
	keys := make([]string, 0, len(c.Fields))
	for k := range c.Fields {
		keys = append(keys, k)
	}
	// deterministic order for tests and dry-run output
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		sb.WriteString(" -f " + shellQuote(k+"="+c.Fields[k]))
	}
	if c.Body != nil {
		raw, _ := json.MarshalIndent(c.Body, "", "  ")
		sb.WriteString(" --input - <<'EOF'\n" + string(raw) + "\nEOF")
	}
	return sb.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// EnableRepoScanning enables secret scanning and push protection on one repo.
// Endpoint verified against GitHub's REST API via `gh api -X PATCH
// repos/{owner}/{repo}` with the security_and_analysis object.
func EnableRepoScanning(owner, repo string) Call {
	return Call{
		Method: "PATCH",
		Path:   "repos/" + owner + "/" + repo,
		Fields: map[string]string{
			"security_and_analysis[secret_scanning][status]":                 "enabled",
			"security_and_analysis[secret_scanning_push_protection][status]": "enabled",
		},
	}
}

// OrgDefaults enables secret scanning and push protection by default for
// new repositories in the org.
func OrgDefaults(org string) Call {
	return Call{
		Method: "PATCH",
		Path:   "orgs/" + org,
		Fields: map[string]string{
			"secret_scanning_enabled_for_new_repositories":                 "true",
			"secret_scanning_push_protection_enabled_for_new_repositories": "true",
		},
	}
}

// Pattern is a custom secret-scanning pattern for an internal token shape.
type Pattern struct {
	Name  string
	Regex string
}

// lookaround matches regex constructs GitHub's Hyperscan engine rejects.
var lookaround = regexp.MustCompile(`\(\?[=!]|\(\?<[=!]`)

// MaxPatternLen keeps patterns simple and within GitHub's documented limits.
const MaxPatternLen = 1000

// ValidatePattern ensures a custom pattern is RE2/Hyperscan-safe: it must
// compile under Go's RE2 engine, contain no lookarounds or backreferences,
// and stay within length limits.
func ValidatePattern(p Pattern) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("pattern name is empty")
	}
	if len(p.Name) > 255 {
		return fmt.Errorf("pattern name %q exceeds 255 chars", p.Name)
	}
	if strings.TrimSpace(p.Regex) == "" {
		return fmt.Errorf("pattern %q: regex is empty", p.Name)
	}
	if len(p.Regex) > MaxPatternLen {
		return fmt.Errorf("pattern %q: regex exceeds %d chars", p.Name, MaxPatternLen)
	}
	if lookaround.MatchString(p.Regex) {
		return fmt.Errorf("pattern %q: lookarounds ((?= (?! (?<= (?<!) are not supported by GitHub's scanner", p.Name)
	}
	if _, err := regexp.Compile(p.Regex); err != nil {
		return fmt.Errorf("pattern %q: not valid RE2: %w", p.Name, err)
	}
	return nil
}

// CreateCustomPatterns builds the bulk-POST call that creates custom
// patterns on a repo. GitHub creates them UNPUBLISHED: publishing (and
// enabling push protection for the pattern) is a UI-only step the caller
// must surface to the user. Requires GitHub Secret Protection on the repo
// (paid) for private repositories.
func CreateCustomPatterns(owner, repo string, patterns []Pattern) (Call, error) {
	if len(patterns) == 0 {
		return Call{}, fmt.Errorf("no patterns given")
	}
	bodies := make([]map[string]string, 0, len(patterns))
	for _, p := range patterns {
		if err := ValidatePattern(p); err != nil {
			return Call{}, err
		}
		bodies = append(bodies, map[string]string{"name": p.Name, "pattern": p.Regex})
	}
	return Call{
		Method: "POST",
		Path:   "repos/" + owner + "/" + repo + "/secret-scanning/custom-patterns",
		Body:   map[string]any{"patterns": bodies},
	}, nil
}

// GhPath returns the gh binary or a loud error when it is missing.
func GhPath() (string, error) {
	p, err := exec.LookPath("gh")
	if err != nil {
		return "", fmt.Errorf("gh CLI not found on PATH — install it (https://cli.github.com) and re-run")
	}
	return p, nil
}

// Authed fails loudly when gh is not authenticated.
func Authed(gh string) error {
	cmd := exec.Command(gh, "auth", "status")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gh is not authenticated: %v\n%s\nrun `gh auth login` first", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Preflight fails loudly when gh is missing or not authed. It runs before
// any dry-run or apply output so both modes validate the same assumptions.
func Preflight() (string, error) {
	gh, err := GhPath()
	if err != nil {
		return "", err
	}
	if err := Authed(gh); err != nil {
		return "", err
	}
	return gh, nil
}

// Exec runs one Call through the gh CLI.
func Exec(gh string, c Call) error {
	args := []string{"api", "--method", c.Method, c.Path}
	for k, v := range c.Fields {
		args = append(args, "-f", k+"="+v)
	}
	var stdin *strings.Reader
	if c.Body != nil {
		args = append(args, "--input", "-")
		raw, err := json.Marshal(c.Body)
		if err != nil {
			return err
		}
		stdin = strings.NewReader(string(raw))
	}
	cmd := exec.Command(gh, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gh api %s %s failed: %v\n%s", c.Method, c.Path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CurrentRepo resolves owner/repo from the checkout in cwd via gh.
func CurrentRepo(gh string) (owner, repo string, err error) {
	out, cmdErr := exec.Command(gh, "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner").CombinedOutput()
	name := strings.TrimSpace(string(out))
	if cmdErr != nil || name == "" || !strings.Contains(name, "/") {
		return "", "", fmt.Errorf("could not determine repo from cwd (not a GitHub checkout?): %v\n%s", cmdErr, name)
	}
	parts := strings.SplitN(name, "/", 2)
	return parts[0], parts[1], nil
}

// ListOrgRepos returns every owner/repo in the org (paginated).
func ListOrgRepos(gh, org string) ([]string, error) {
	out, err := exec.Command(gh, "api", "orgs/"+org+"/repos?per_page=100", "--paginate", "--jq", ".[].full_name").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list repos for org %q: %v\n%s", org, err, strings.TrimSpace(string(out)))
	}
	var repos []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			repos = append(repos, line)
		}
	}
	return repos, nil
}

// BypassPolicyChecklist is the standing bypass-policy configuration. It has
// no public REST endpoint, so it is surfaced as explicit manual steps rather
// than an invented API call.
func BypassPolicyChecklist() []string {
	return []string{
		"Org settings → Code security → Push protection: keep \"Allow bypasses\" on, enable \"Require bypass reason\" — every bypass is audit-logged.",
		"Delegated bypass (Enterprise): grant bypass privileges to a named reviewer group instead of all writers.",
		"Triaging an alert is not rotation: dismissing ≠ revoking — rotate the credential, then resolve the alert.",
	}
}
