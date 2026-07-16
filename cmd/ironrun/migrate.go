package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/migration"
)

func migrateCmd() *cobra.Command {
	var apply bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Preview or apply a reversible policy-v2 migration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			preview, err := migration.Plan(policyPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Policy: %s\nEnvironment: %s\n", preview.PolicyPath, preview.Environment)
			if len(preview.Mappings) == 0 {
				fmt.Fprintln(out, "No legacy secret aliases need value migration.")
			} else {
				fmt.Fprintln(out, "Alias-to-entry mapping (values hidden):")
				for _, item := range preview.Mappings {
					action := "verify existing encrypted entry"
					if item.Copied {
						action = "copy transactionally into encrypted entry"
					}
					fmt.Fprintf(out, "  %s -> %s (%s; %s)\n", item.Alias, item.Entry, item.Kind, action)
				}
			}
			if !apply {
				fmt.Fprintln(out, "Preview only. Run `ironrun migrate --apply` to write an ignored backup, verify encrypted storage, and update the policy.")
				return nil
			}
			manifest, err := migration.Apply(policyPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Migration %s applied and verified. Legacy values were not deleted.\n", manifest.ID)
			fmt.Fprintf(out, "Rollback: ironrun migrate rollback %s\n", manifest.ID)
			fmt.Fprintf(out, "After dogfooding, permanently finish: ironrun migrate cleanup %s\n", manifest.ID)
			return nil
		},
	}
	cmd.Flags().BoolVar(&apply, "apply", false, "apply the previewed migration transactionally")
	cmd.AddCommand(migrateRollbackCmd(), migrateCleanupCmd())
	return cmd
}

func migrateRollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rollback [MIGRATION_ID]",
		Short: "Restore the version-1 policy and remove copied entries",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) == 1 {
				id = args[0]
			}
			manifest, err := migration.Rollback(policyPath, id)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Migration %s rolled back and verified.\n", manifest.ID)
			return nil
		},
	}
}

func migrateCleanupCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "cleanup [MIGRATION_ID]",
		Short: "Delete legacy aliases and permanently end rollback",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return fmt.Errorf("cleanup permanently ends rollback; rerun with --yes after verifying version 2")
			}
			id := ""
			if len(args) == 1 {
				id = args[0]
			}
			manifest, err := migration.Cleanup(policyPath, id)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Migration %s cleaned. Legacy aliases are deleted; rollback is no longer available.\n", manifest.ID)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm permanent legacy deletion")
	return cmd
}
