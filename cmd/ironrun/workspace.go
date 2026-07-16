package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/project"
	irontui "github.com/generalized-labs/ironrun/internal/tui"
)

func runGlobalWorkspace(focusInbox bool) error {
	registry, err := project.DefaultStore()
	if err != nil {
		return err
	}
	if cwd, cwdErr := os.Getwd(); cwdErr == nil {
		if _, statErr := os.Stat(filepath.Join(cwd, "ironrun.yml")); statErr == nil {
			_, _ = registry.Register(cwd)
		}
	}
	selected, err := irontui.RunGlobal(registry, focusInbox)
	if err != nil || selected == "" {
		return err
	}
	return runTUI(filepath.Join(selected, "ironrun.yml"))
}

func openCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "open [PROJECT|PATH]",
		Short: "Register or open a project workspace",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := mustWorkingDir()
			if len(args) == 1 {
				query = args[0]
			}
			registry, err := project.DefaultStore()
			if err != nil {
				return err
			}
			var selected project.Project
			if info, statErr := os.Stat(query); statErr == nil && info.IsDir() {
				selected, err = registry.Register(query)
			} else {
				selected, err = registry.Resolve(query)
			}
			if err != nil {
				return fmt.Errorf("open project: %w", err)
			}
			return runTUI(filepath.Join(selected.Path, "ironrun.yml"))
		},
	}
}

func inboxCmd() *cobra.Command {
	return &cobra.Command{Use: "inbox", Short: "Open the global waiting-request inbox", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return runGlobalWorkspace(true)
	}}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show a value-blind project summary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			registry, err := project.DefaultStore()
			if err != nil {
				return err
			}
			p, err := registry.Register(mustWorkingDir())
			if err != nil {
				return fmt.Errorf("not an accessible project: %w", err)
			}
			m, err := envset.Open(p.Path)
			if err != nil {
				return fmt.Errorf("encrypted environment unavailable: %w", err)
			}
			active := "none"
			configured := 0
			if set, activeErr := m.Active(); activeErr == nil {
				active = set.Name
				configured = len(set.Entries)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Project: %s (%s)\nPath: %s\nEnvironment: %s\nConfigured items: %d\n", p.Name, p.ID, p.Path, active, configured)
			return nil
		},
	}
}

func importCmd() *cobra.Command {
	var keysCSV string
	var yes bool
	cmd := &cobra.Command{
		Use:   "import [PATH]",
		Short: "Preview and encrypt selected dotenv keys into the active environment",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ".env"
			if len(args) == 1 {
				path = args[0]
			}
			manager, active, err := activeEnvironment()
			if err != nil {
				return err
			}
			entries, err := envset.ParseDotenv(path, "")
			if err != nil {
				return fmt.Errorf("cannot import %s: %w", path, err)
			}
			selected := selectDotenvEntries(entries, keysCSV)
			if len(selected) == 0 {
				return fmt.Errorf("no selected keys were found in %s", path)
			}
			names := make([]string, 0, len(selected))
			for _, entry := range selected {
				if _, exists := manager.Entry(active.Name, entry.Key); exists {
					return fmt.Errorf("%s is already configured; use `ironrun env rotate %s %s` to replace it", entry.Key, active.Name, entry.Key)
				}
				names = append(names, entry.Key)
			}
			sort.Strings(names)
			fmt.Fprintf(cmd.OutOrStdout(), "Import into %s (values hidden): %s\n", active.Name, strings.Join(names, ", "))
			if !yes {
				ok, confirmErr := confirm("Encrypt these keys? [y/N] ")
				if confirmErr != nil {
					return confirmErr
				}
				if !ok {
					return fmt.Errorf("import cancelled")
				}
			}
			var added []string
			for i := range selected {
				entry := &selected[i]
				if err := manager.Put(active.Name, entry.Key, entry.Value); err != nil {
					for _, key := range added {
						_ = manager.DeleteKey(active.Name, key)
					}
					return fmt.Errorf("encrypted import rolled back at %s: %w", entry.Key, err)
				}
				stored, verifyErr := manager.Get(active.Name, entry.Key)
				if verifyErr != nil || stored != entry.Value {
					for _, key := range append(added, entry.Key) {
						_ = manager.DeleteKey(active.Name, key)
					}
					return fmt.Errorf("encrypted verification failed for %s; import rolled back", entry.Key)
				}
				entry.Value, stored = "", ""
				added = append(added, entry.Key)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Encrypted and verified %d keys. Plaintext source %s still exists; protect or remove it when safe.\n", len(added), path)
			return nil
		},
	}
	cmd.Flags().StringVar(&keysCSV, "keys", "", "comma-separated keys to import (default: all)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the preview non-interactively")
	return cmd
}

func selectDotenvEntries(entries []envset.DotenvEntry, csv string) []envset.DotenvEntry {
	if strings.TrimSpace(csv) == "" {
		return append([]envset.DotenvEntry(nil), entries...)
	}
	wanted := map[string]bool{}
	for _, key := range strings.Split(csv, ",") {
		wanted[strings.TrimSpace(key)] = true
	}
	selected := make([]envset.DotenvEntry, 0, len(wanted))
	for _, entry := range entries {
		if wanted[entry.Key] {
			selected = append(selected, entry)
		}
	}
	return selected
}

func projectsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "projects", Short: "Repair or remove registered project paths"}
	cmd.AddCommand(&cobra.Command{Use: "list", Short: "List registered projects", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		registry, err := project.DefaultStore()
		if err != nil {
			return err
		}
		projects, err := registry.List()
		if err != nil {
			return err
		}
		for _, p := range projects {
			state := "ready"
			if _, err := os.Stat(p.Path); err != nil {
				state = "missing"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s  %s\n", p.ID, p.Name, state, p.Path)
		}
		return nil
	}})
	cmd.AddCommand(&cobra.Command{Use: "repair ID PATH", Short: "Update a moved checkout without changing its project ID", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		registry, err := project.DefaultStore()
		if err != nil {
			return err
		}
		p, err := registry.Repair(args[0], args[1])
		if err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Repaired %s -> %s\n", p.ID, p.Path)
		}
		return err
	}})
	cmd.AddCommand(&cobra.Command{Use: "remove ID", Short: "Remove a missing or unwanted checkout from the registry", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		registry, err := project.DefaultStore()
		if err != nil {
			return err
		}
		return registry.Remove(args[0])
	}})
	return cmd
}
