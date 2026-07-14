package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
)

func envCmd() *cobra.Command {
	c := &cobra.Command{Use: "env", Aliases: []string{"vault"}, Short: "Manage project-scoped environment sets without exposing values"}
	c.AddCommand(envInitCmd(), envCreateCmd(), envListCmd(), envUseCmd(), envStatusCmd(), envSetCmd(), envFileCmd(), envImportCmd(), envExportCmd(), envCloneCmd(), envRotateCmd(), envDeleteCmd(), envRemoveCmd(), envPruneCmd(), envDoctorCmd())
	return c
}

func openEnvManager() (*envset.Manager, error) { return envset.Open(mustWorkingDir()) }

func envInitCmd() *cobra.Command {
	return &cobra.Command{Use: "init [NAME]", Aliases: []string{"enable"}, Short: "Register this project and create its first environment set", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		name := "dev"
		if len(args) == 1 {
			name = args[0]
		}
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		s, err := m.Ensure(name)
		if err != nil {
			return err
		}
		if err := ensureEnvGitignore(m.Root); err != nil {
			return err
		}
		if err := m.Use(s.Name); err != nil {
			return err
		}
		if err := attachPolicyToActiveEnvironment(policyPath); err != nil {
			return err
		}
		fmt.Printf("Project registered: %s\nActive environment: %s\nSecure store: %s\n", identitySummary(m.Meta.Identity), s.Name, m.Store.Name())
		return nil
	}}
}

func envCreateCmd() *cobra.Command {
	var temporary bool
	var ttl time.Duration
	c := &cobra.Command{Use: "create NAME", Aliases: []string{"new"}, Short: "Create a persistent or expiring environment set", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		s, err := m.Create(args[0], temporary, ttl)
		if err != nil {
			return err
		}
		fmt.Printf("Created %s environment %q", kind(s), s.Name)
		if s.ExpiresAt != nil {
			fmt.Printf(" (expires %s)", s.ExpiresAt.Format(time.RFC3339))
		}
		fmt.Println()
		return nil
	}}
	c.Flags().BoolVar(&temporary, "temporary", false, "expire this set automatically")
	c.Flags().DurationVar(&ttl, "ttl", envset.DefaultTTL, "lifetime for temporary sets")
	return c
}

func envListCmd() *cobra.Command {
	return &cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "List environment sets without values", RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		return printEnvironmentList(m)
	}}
}

func printEnvironmentList(m *envset.Manager) error {
	for _, name := range m.Names() {
		s, _ := m.Set(name)
		marker := " "
		if name == m.Meta.Active {
			marker = "*"
		}
		expiry := "-"
		if s.ExpiresAt != nil {
			expiry = s.ExpiresAt.Format(time.RFC3339)
			if m.Expired(s) {
				expiry += " (expired)"
			}
		}
		fmt.Printf("%s %-16s %-10s keys=%d created=%s expires=%s\n", marker, name, kind(s), len(s.Keys), s.CreatedAt.Format(time.RFC3339), expiry)
	}
	fmt.Printf("project: %s\n", identitySummary(m.Meta.Identity))
	return nil
}

func environmentSetTarget(m *envset.Manager, args []string) (string, string, error) {
	if len(args) == 2 {
		return args[0], args[1], nil
	}
	if m.Meta.Active == "" {
		return "", "", fmt.Errorf("no active environment; run `ironrun new NAME` first")
	}
	return m.Meta.Active, args[0], nil
}

func envUseCmd() *cobra.Command {
	return &cobra.Command{Use: "use NAME", Aliases: []string{"switch"}, Short: "Select the active set for this project", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		if err := m.Use(args[0]); err != nil {
			return err
		}
		fmt.Printf("Active environment: %s\n", args[0])
		return nil
	}}
}

func envStatusCmd() *cobra.Command {
	return &cobra.Command{Use: "status [NAME]", Aliases: []string{"show"}, Short: "Show configured keys and policy coverage, never values", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		name := m.Meta.Active
		if len(args) == 1 {
			name = args[0]
		}
		if name == "" {
			return fmt.Errorf("no active environment set")
		}
		s, ok := m.Set(name)
		if !ok {
			return fmt.Errorf("environment set %q not found", name)
		}
		keys := append([]string(nil), s.Keys...)
		if f, loadErr := policy.Load(policyPath); loadErr == nil {
			keys = policyKeys(f)
		}
		sort.Strings(keys)
		for _, key := range keys {
			entry, typed := m.Entry(name, key)
			var getErr error
			kind := "env"
			if typed && entry.Kind == envset.EntryFile {
				kind = "file"
				_, getErr = m.GetBytes(name, key)
			} else {
				_, getErr = m.Get(name, key)
			}
			state := "missing"
			if getErr == nil {
				state = "configured"
			}
			fmt.Printf("%s: %s (%s)\n", key, state, kind)
		}
		fmt.Printf("set: %s (%s)\n", name, kind(s))
		return nil
	}}
}

func envFileCmd() *cobra.Command {
	return &cobra.Command{Use: "file [NAME] KEY PATH", Short: "Encrypt one owner-only file secret", Args: cobra.RangeArgs(2, 3), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		var environment, target, path string
		if len(args) == 3 {
			environment, target, path = args[0], args[1], args[2]
		} else {
			if m.Meta.Active == "" {
				return fmt.Errorf("no active environment; run `ironrun new NAME` first")
			}
			environment, target, path = m.Meta.Active, args[0], args[1]
		}
		if err := storeFileEntry(m, environment, target, path); err != nil {
			return err
		}
		fmt.Printf("Encrypted file %s in %s. Source file was not deleted.\n", target, environment)
		return nil
	}}
}

func envSetCmd() *cobra.Command {
	var fromStdin, unsafe bool
	c := &cobra.Command{Use: "set [NAME] KEY", Aliases: []string{"add"}, Short: "Store one value using masked input", Args: cobra.RangeArgs(1, 2), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		name, key, err := environmentSetTarget(m, args)
		if err != nil {
			return err
		}
		value, err := readSecret(fromStdin, unsafe)
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("value cannot be empty")
		}
		if err := m.Put(name, key, value); err != nil {
			return err
		}
		fmt.Printf("Saved %s in %s. Value is never displayed.\n", key, name)
		return nil
	}}
	c.Flags().BoolVar(&fromStdin, "from-stdin", false, "read from stdin (requires --unsafe)")
	c.Flags().BoolVar(&unsafe, "unsafe", false, "acknowledge piped input risk")
	return c
}

func envImportCmd() *cobra.Command {
	var allowProjectFile bool
	c := &cobra.Command{Use: "import NAME PATH", Short: "Import an owner-only dotenv file without displaying values", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		root := m.Root
		if allowProjectFile {
			root = ""
		}
		entries, err := envset.ParseDotenv(args[1], root)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return fmt.Errorf("no environment keys found")
		}
		fmt.Printf("Import %d keys into %q: %s\n", len(entries), args[0], keysOf(entries))
		ok, err := confirm("Continue? [y/N] ")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("import cancelled")
		}
		for _, entry := range entries {
			if err := m.Put(args[0], entry.Key, entry.Value); err != nil {
				return err
			}
		}
		fmt.Printf("Imported %d keys. Values are never displayed.\n", len(entries))
		return nil
	}}
	c.Flags().BoolVar(&allowProjectFile, "allow-project-file", false, "allow importing a file inside the project (still requires owner-only permissions)")
	return c
}

func envExportCmd() *cobra.Command {
	return &cobra.Command{Use: "export NAME PATH", Short: "Write a redacted key template (never values)", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		s, ok := m.Set(args[0])
		if !ok {
			return fmt.Errorf("environment set %q not found", args[0])
		}
		keys := s.Keys
		if len(keys) == 0 {
			if f, loadErr := policy.Load(policyPath); loadErr == nil {
				keys = policyKeys(f)
			}
		}
		if err := m.Template(args[0], args[1], keys); err != nil {
			return err
		}
		fmt.Printf("Wrote redacted template with %d keys. Values were not exported.\n", len(keys))
		return nil
	}}
}
func envCloneCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{Use: "clone SOURCE DEST", Short: "Clone values into another set after confirmation", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		if !yes {
			ok, confirmErr := confirm("Clone secret values into the destination? [y/N] ")
			if confirmErr != nil {
				return confirmErr
			}
			if !ok {
				return fmt.Errorf("clone cancelled")
			}
		}
		if err := m.Clone(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("Cloned %q to %q. Values are never displayed.\n", args[0], args[1])
		return nil
	}}
	c.Flags().BoolVar(&yes, "yes", false, "skip confirmation")
	return c
}
func envRotateCmd() *cobra.Command {
	return &cobra.Command{Use: "rotate NAME KEY", Short: "Replace one value using masked input", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		value, err := readSecret(false, false)
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("value cannot be empty")
		}
		if err := m.Put(args[0], args[1], value); err != nil {
			return err
		}
		fmt.Printf("Rotated %s. Value is never displayed.\n", args[1])
		return nil
	}}
}
func envDeleteCmd() *cobra.Command {
	return &cobra.Command{Use: "delete NAME KEY", Short: "Delete one value after confirmation", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		ok, err := confirm("Delete this environment key? [y/N] ")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("delete cancelled")
		}
		if err := m.DeleteKey(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("Deleted %s.\n", args[1])
		return nil
	}}
}
func envRemoveCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{Use: "remove NAME", Short: "Remove an entire environment set", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		if !yes {
			ok, confirmErr := confirm("Delete all values in this environment set? [y/N] ")
			if confirmErr != nil {
				return confirmErr
			}
			if !ok {
				return fmt.Errorf("remove cancelled")
			}
		}
		if err := m.Remove(args[0]); err != nil {
			return err
		}
		fmt.Printf("Removed %s.\n", args[0])
		return nil
	}}
	c.Flags().BoolVar(&yes, "yes", false, "skip confirmation")
	return c
}
func envPruneCmd() *cobra.Command {
	return &cobra.Command{Use: "prune", Short: "Delete expired temporary sets", RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		n, err := m.Prune()
		if err != nil {
			return err
		}
		fmt.Printf("Pruned %d expired environment set(s).\n", n)
		return nil
	}}
}
func envDoctorCmd() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Validate project identity, storage, expiry, and policy coverage", RunE: func(cmd *cobra.Command, args []string) error {
		m, err := openEnvManager()
		if err != nil {
			return err
		}
		if removed, pruneErr := m.Prune(); pruneErr != nil {
			return pruneErr
		} else if removed > 0 {
			fmt.Printf("Pruned %d expired environment set(s).\n", removed)
		}
		fmt.Printf("✓ project %s\n✓ secure store %s\n", identitySummary(m.Meta.Identity), m.Store.Name())
		if m.Meta.Active != "" {
			if _, activeErr := m.Active(); activeErr != nil {
				return activeErr
			}
			fmt.Printf("✓ active set %s\n", m.Meta.Active)
		} else {
			fmt.Println("! no active set")
		}
		return nil
	}}
}

func policyKeys(f *policy.File) []string {
	seen := map[string]bool{}
	for _, cmd := range f.Commands {
		for _, alias := range cmd.Secrets {
			if decl, ok := f.Secrets[alias]; ok {
				seen[decl.Env] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	return out
}
func kind(s envset.Set) string {
	if s.Temporary {
		return "temporary"
	}
	return "persistent"
}
func identitySummary(i envset.Identity) string {
	if i.RemoteURL == "" {
		return i.CanonicalPath
	}
	return i.RemoteURL + " @ " + i.CanonicalPath
}
func keysOf(entries []envset.DotenvEntry) string {
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
func confirm(prompt string) (bool, error) {
	if _, err := os.Stdin.Stat(); err != nil {
		return false, err
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
func ensureEnvGitignore(root string) error {
	dir := filepath.Join(root, ".ironrun")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.WriteFile(path, []byte("*\n!.gitignore\n"), 0600)
	}
	return nil
}

func attachPolicyToActiveEnvironment(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read policy for environment setup: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "environment_set:") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + "environment_set: active"
			found = true
		}
	}
	if !found {
		lines = append(lines, "environment_set: active")
	}
	mode := os.FileMode(0600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), mode); err != nil {
		return fmt.Errorf("enable environment sets in policy: %w", err)
	}
	return nil
}
