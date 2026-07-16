package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/daemon"
)

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "daemon", Short: "Manage the value-blind per-user Ironrun service"}
	cmd.AddCommand(
		&cobra.Command{Use: "run", Short: "Run the service in the foreground", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.Serve(cmd.Context())
		}},
		daemonInstallCmd(),
		&cobra.Command{Use: "start", Short: "Start the installed user service", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return daemon.Start() }},
		&cobra.Command{Use: "stop", Short: "Stop the installed user service", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return daemon.Stop() }},
		&cobra.Command{Use: "uninstall", Short: "Stop and remove the user service", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return daemon.Uninstall() }},
		&cobra.Command{Use: "status", Short: "Check service health without exposing values", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
			defer cancel()
			if err := daemon.Ping(ctx); err != nil {
				return fmt.Errorf("daemon is not reachable: %w\nRepair: ironrun daemon start", err)
			}
			socket, _ := daemon.SocketPath()
			fmt.Fprintf(cmd.OutOrStdout(), "Daemon healthy: %s\nSecret-value RPC fields: none\n", socket)
			return nil
		}},
	)
	return cmd
}

func daemonInstallCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{Use: "install", Short: "Preview and install a launchd/systemd user service", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		path, content, err := daemon.UnitPreview()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Service file: %s\n\n%s\n", path, content)
		if !yes {
			ok, confirmErr := confirm("Install and start this owner service? [y/N] ")
			if confirmErr != nil {
				return confirmErr
			}
			if !ok {
				return fmt.Errorf("service installation cancelled")
			}
		}
		installed, err := daemon.Install()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Installed and started %s\n", installed)
		return nil
	}}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the preview non-interactively")
	return cmd
}
