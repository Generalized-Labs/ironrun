package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/project"
	irontui "github.com/generalized-labs/ironrun/internal/tui"
)

func tuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "dashboard",
		Aliases: []string{"tui"},
		Short:   "Open the Ironrun local vault and agent-access control room",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(policyPath)
		},
	}
}

func runTUI(path string) error {
	if err := bootstrapFirstRun(path); err != nil {
		return err
	}
	return irontui.Run(path)
}

func bootstrapFirstRun(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err == nil {
		return registerProject(filepath.Dir(abs))
	} else if !os.IsNotExist(err) {
		return err
	}
	root := filepath.Dir(abs)
	envVars := detectEnvVars(root)
	content := generatePolicy(detectCommands(root, envVars), envVars)
	if err := os.WriteFile(abs, []byte(content), 0600); err != nil {
		return fmt.Errorf("create first-run policy: %w", err)
	}
	if err := initializeLocalEnvironment(root); err != nil {
		_ = os.Remove(abs)
		return err
	}
	if err := registerProject(root); err != nil {
		return fmt.Errorf("register project: %w", err)
	}
	_ = registerClaudeMCP(root)
	fmt.Println("Created ironrun.yml and encrypted environment dev. Opening the control room…")
	return nil
}

func registerProject(root string) error {
	registry, err := project.DefaultStore()
	if err != nil {
		return err
	}
	_, err = registry.Register(root)
	return err
}

func initializeLocalEnvironment(root string) error {
	manager, err := envset.Open(root)
	if err != nil {
		return fmt.Errorf("initialize encrypted environment: %w", err)
	}
	set, err := manager.Ensure("dev")
	if err != nil {
		return err
	}
	if err := manager.Use(set.Name); err != nil {
		return err
	}
	return ensureEnvGitignore(root)
}
