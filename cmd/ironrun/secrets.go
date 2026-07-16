package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/policy"
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

func secretsCmd() *cobra.Command {
	root := &cobra.Command{Use: "secrets", Short: "Store and manage host-side secret values"}
	root.AddCommand(secretSetCmd(), secretStatusCmd(), secretDeleteCmd(), secretRotateCmd())
	return root
}

func secretSetCmd() *cobra.Command {
	var backend string
	var fromStdin, unsafe bool
	c := &cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret without placing its value in the policy or agent context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return fmt.Errorf("secret name cannot be empty")
			}
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}
			if f.UsesEnvironmentEntries() {
				if _, _, ok := f.SecretBinding(name); !ok {
					return fmt.Errorf("environment entry %q is not bound to an approved command", name)
				}
				value, err := readSecret(fromStdin, unsafe)
				if err != nil {
					return err
				}
				if value == "" {
					return fmt.Errorf("secret value cannot be empty")
				}
				manager, active, err := activeEnvironment()
				if err != nil {
					return err
				}
				if err := manager.Put(active.Name, name, value); err != nil {
					return err
				}
				fmt.Printf("Saved %q in encrypted environment %s. Value is never displayed.\n", name, active.Name)
				return nil
			}
			decl, ok := f.Secrets[name]
			if !ok {
				return fmt.Errorf("secret %q is not declared in policy", name)
			}
			if decl.Env == "" {
				return fmt.Errorf("secret %q has no env binding", name)
			}
			store, err := secretstore.Open(policyPath, chooseStore(backend, decl.Store))
			if err != nil {
				return err
			}
			value, err := readSecret(fromStdin, unsafe)
			if err != nil {
				return err
			}
			if value == "" {
				return fmt.Errorf("secret value cannot be empty")
			}
			if err := store.Set(name, value); err != nil {
				return err
			}
			fmt.Printf("Saved %q in %s. Value is never displayed.\n", name, store.Name())
			fmt.Printf("Policy binding verified for %d command(s).\n", len(decl.Allow))
			return nil
		},
	}
	c.Flags().StringVar(&backend, "provider", "auto", "storage backend: auto, keychain, or envfile")
	c.Flags().BoolVar(&fromStdin, "from-stdin", false, "read from stdin (requires --unsafe)")
	c.Flags().BoolVar(&unsafe, "unsafe", false, "acknowledge that piped input can be captured by the invoking process")
	return c
}

func secretStatusCmd() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show configured secret names and bindings, never values", RunE: func(cmd *cobra.Command, args []string) error {
		f, err := policy.Load(policyPath)
		if err != nil {
			return err
		}
		if f.UsesEnvironmentEntries() {
			manager, active, err := activeEnvironment()
			if err != nil {
				return err
			}
			for _, entry := range active.Entries {
				state := "missing"
				if entry.Kind == "file" {
					if _, getErr := manager.GetBytes(active.Name, entry.Name); getErr == nil {
						state = "configured"
					}
				} else if _, getErr := manager.Get(active.Name, entry.Name); getErr == nil {
					state = "configured"
				}
				fmt.Printf("%s: %s (kind=%s, target=%s, environment=%s)\n", entry.Name, state, entry.Kind, entry.Target, active.Name)
			}
			return nil
		}
		for name, decl := range f.Secrets {
			store, openErr := secretstore.Open(policyPath, decl.Store)
			state := "unavailable"
			backend := "unknown"
			if openErr == nil {
				backend = store.Name()
				if _, getErr := store.Get(name); getErr == nil {
					state = "configured"
				} else if getErr == secretstore.ErrMissing {
					state = "missing"
				}
			}
			fmt.Printf("%s: %s (env=%s, backend=%s, commands=%d)\n", name, state, decl.Env, backend, len(decl.Allow))
		}
		return nil
	}}
}

func secretDeleteCmd() *cobra.Command {
	return secretMutationCmd("delete", "Delete a stored secret", func(s secretstore.Store, name string) error { return s.Delete(name) })
}
func secretRotateCmd() *cobra.Command {
	return &cobra.Command{Use: "rotate NAME", Short: "Replace a stored secret using masked input", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		f, err := policy.Load(policyPath)
		if err != nil {
			return err
		}
		if f.UsesEnvironmentEntries() {
			if _, _, ok := f.SecretBinding(args[0]); !ok {
				return fmt.Errorf("environment entry %q is not bound to an approved command", args[0])
			}
			value, err := readSecret(false, false)
			if err != nil {
				return err
			}
			manager, active, err := activeEnvironment()
			if err != nil {
				return err
			}
			if err := manager.Put(active.Name, args[0], value); err != nil {
				return err
			}
			fmt.Printf("Rotated %q in %s. Value is never displayed.\n", args[0], active.Name)
			return nil
		}
		decl, ok := f.Secrets[args[0]]
		if !ok {
			return fmt.Errorf("secret %q is not declared in policy", args[0])
		}
		store, err := secretstore.Open(policyPath, decl.Store)
		if err != nil {
			return err
		}
		value, err := readSecret(false, false)
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("secret value cannot be empty")
		}
		if err := store.Set(args[0], value); err != nil {
			return err
		}
		fmt.Printf("Rotated %q. Value is never displayed.\n", args[0])
		return nil
	}}
}
func secretMutationCmd(use, short string, fn func(secretstore.Store, string) error) *cobra.Command {
	return &cobra.Command{Use: use + " NAME", Short: short, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		f, err := policy.Load(policyPath)
		if err != nil {
			return err
		}
		if f.UsesEnvironmentEntries() {
			manager, active, err := activeEnvironment()
			if err != nil {
				return err
			}
			if err := manager.DeleteKey(active.Name, args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted %q. Future sealed runs will create a missing-secret request.\n", args[0])
			return nil
		}
		decl, ok := f.Secrets[args[0]]
		if !ok {
			return fmt.Errorf("secret %q is not declared in policy", args[0])
		}
		s, err := secretstore.Open(policyPath, decl.Store)
		if err != nil {
			return err
		}
		if err := fn(s, args[0]); err != nil {
			return err
		}
		fmt.Printf("Deleted %q. Future sealed runs will fail with secret_missing.\n", args[0])
		return nil
	}}
}

func chooseStore(flag, declared string) string {
	if flag != "auto" {
		return flag
	}
	if declared != "" {
		return declared
	}
	return "auto"
}

func readSecret(fromStdin, unsafe bool) (string, error) {
	if fromStdin {
		if !unsafe {
			return "", fmt.Errorf("--from-stdin requires explicit --unsafe")
		}
		b, err := io.ReadAll(os.Stdin)
		return strings.TrimRight(string(b), "\r\n"), err
	}
	f, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if f.Mode()&os.ModeCharDevice == 0 {
		return "", fmt.Errorf("refusing non-terminal input; use --from-stdin --unsafe explicitly")
	}
	fmt.Fprint(os.Stderr, "Secret value (input hidden): ")
	_ = exec.Command("stty", "-echo").Run()
	defer func() { _ = exec.Command("stty", "echo").Run(); fmt.Fprintln(os.Stderr) }()
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
