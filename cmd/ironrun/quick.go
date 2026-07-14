package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/envset"
)

func quickAddCmd() *cobra.Command {
	var fromStdin, unsafe bool
	c := &cobra.Command{
		Use:   "add KEY",
		Short: "Add a secret to the active environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, active, err := activeEnvironment()
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
			if err := m.Put(active.Name, args[0], value); err != nil {
				return err
			}
			fmt.Printf("Saved %s in %s. Value is never displayed.\n", args[0], active.Name)
			return nil
		},
	}
	c.Flags().BoolVar(&fromStdin, "from-stdin", false, "read from stdin (requires --unsafe)")
	c.Flags().BoolVar(&unsafe, "unsafe", false, "acknowledge piped input risk")
	return c
}

func quickNewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "new NAME",
		Short: "Create and activate a persistent environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := createAndActivateEnvironment(args[0], false, 0)
			return err
		},
	}
}

func quickSessionCmd() *cobra.Command {
	var ttl time.Duration
	c := &cobra.Command{
		Use:   "session [NAME]",
		Short: "Create and activate an expiring session environment",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := "session-" + time.Now().Format("20060102-150405")
			if len(args) == 1 {
				name = args[0]
			}
			_, err := createAndActivateEnvironment(name, true, ttl)
			return err
		},
	}
	c.Flags().DurationVar(&ttl, "ttl", envset.DefaultTTL, "how long the session remains usable")
	return c
}

func quickUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use NAME",
		Short: "Switch the active environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := openEnvManager()
			if err != nil {
				return err
			}
			if err := m.Use(args[0]); err != nil {
				return err
			}
			fmt.Printf("Active environment: %s\n", args[0])
			return nil
		},
	}
}

func quickEnvsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "envs",
		Aliases: []string{"ls"},
		Short:   "List environments without showing values",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := openEnvManager()
			if err != nil {
				return err
			}
			return printEnvironmentList(m)
		},
	}
}

func activeEnvironment() (*envset.Manager, envset.Set, error) {
	m, err := openEnvManager()
	if err != nil {
		return nil, envset.Set{}, err
	}
	if m.Meta.Active == "" {
		if _, err := m.Ensure("dev"); err != nil {
			return nil, envset.Set{}, err
		}
		if err := m.Use("dev"); err != nil {
			return nil, envset.Set{}, err
		}
		if err := ensureEnvGitignore(m.Root); err != nil {
			return nil, envset.Set{}, err
		}
		if err := attachPolicyToActiveEnvironment(policyPath); err != nil {
			return nil, envset.Set{}, err
		}
		fmt.Println("Created and activated environment: dev")
	}
	active, err := m.Active()
	return m, active, err
}

func createAndActivateEnvironment(name string, temporary bool, ttl time.Duration) (envset.Set, error) {
	m, err := openEnvManager()
	if err != nil {
		return envset.Set{}, err
	}
	s, err := m.Create(name, temporary, ttl)
	if err != nil {
		return envset.Set{}, err
	}
	if err := m.Use(name); err != nil {
		return envset.Set{}, err
	}
	if err := ensureEnvGitignore(m.Root); err != nil {
		return envset.Set{}, err
	}
	if err := attachPolicyToActiveEnvironment(policyPath); err != nil {
		return envset.Set{}, err
	}
	if s.ExpiresAt == nil {
		fmt.Printf("Created and activated environment: %s\n", name)
	} else {
		fmt.Printf("Created and activated session: %s (expires %s)\n", name, s.ExpiresAt.Format(time.RFC3339))
	}
	return s, nil
}
