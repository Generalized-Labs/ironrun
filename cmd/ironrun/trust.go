package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	accessctl "github.com/generalized-labs/ironrun/internal/access"
)

// trustCmd is the everyday control surface for broad, revocable agent access.
// The older `access`/`agents` commands remain available for strict leases.
func trustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage trusted agent workspace sessions",
		Long:  "Grant, pause, extend, or revoke temporary agent access to the current project's selected environment. Trusted agents can run normal local commands with secrets injected below agent visibility.",
	}
	cmd.AddCommand(trustListCmd(), trustGrantCmd(), trustPauseCmd(), trustExtendCmd(), trustRevokeCmd())
	return cmd
}

func trustListCmd() *cobra.Command {
	return &cobra.Command{Use: "list", Aliases: []string{"status"}, Short: "List trusted workspace sessions", RunE: func(cmd *cobra.Command, args []string) error {
		manager, err := openAccessManager()
		if err != nil {
			return err
		}
		grants, err := manager.WorkspaceGrants("")
		if err != nil {
			return err
		}
		if len(grants) == 0 {
			fmt.Println("No trusted agent sessions.")
			return nil
		}
		sort.Slice(grants, func(i, j int) bool { return grants[i].ExpiresAt.Before(grants[j].ExpiresAt) })
		now := time.Now().UTC()
		for _, grant := range grants {
			status := "active"
			if grant.RevokedAt != nil {
				status = "revoked"
			} else if grant.PausedAt != nil {
				status = "paused"
			} else if !now.Before(grant.ExpiresAt) {
				status = "expired"
			}
			fmt.Printf("%s  %s  env=%s session=%s network=%s expires=%s\n", grant.ID, status, grant.Environment, shortAccessID(grant.SessionID), grant.Network, grant.ExpiresAt.Local().Format(time.RFC3339))
		}
		return nil
	}}
}

func trustGrantCmd() *cobra.Command {
	var ttl time.Duration
	cmd := &cobra.Command{Use: "grant REQUEST_ID", Short: "Trust a pending agent session for this environment", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		manager, err := openAccessManager()
		if err != nil {
			return err
		}
		grant, err := manager.ApproveWorkspace(args[0], ttl)
		if err != nil {
			return err
		}
		fmt.Printf("Trusted session %s for environment %s until %s. Normal network access is enabled; revoke anytime with `ironrun trust revoke %s`.\n", shortAccessID(grant.SessionID), grant.Environment, grant.ExpiresAt.Local().Format(time.RFC3339), grant.ID)
		return nil
	}}
	cmd.Flags().DurationVar(&ttl, "ttl", accessctl.DefaultWorkspaceTTL, "trusted-session lifetime (maximum 24h)")
	return cmd
}

func trustPauseCmd() *cobra.Command {
	return &cobra.Command{Use: "pause TRUST_ID", Short: "Pause a trusted session without revoking it", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		manager, err := openAccessManager()
		if err != nil {
			return err
		}
		if err := manager.PauseWorkspace(args[0], true); err != nil {
			return err
		}
		fmt.Printf("Paused %s. Use `ironrun trust extend %s --ttl 2h` to resume with a fresh expiry.\n", args[0], args[0])
		return nil
	}}
}

func trustExtendCmd() *cobra.Command {
	var ttl time.Duration
	cmd := &cobra.Command{Use: "extend TRUST_ID", Short: "Resume or extend a trusted session from now", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		manager, err := openAccessManager()
		if err != nil {
			return err
		}
		grant, err := manager.ExtendWorkspace(args[0], ttl)
		if err != nil {
			return err
		}
		if err := manager.PauseWorkspace(args[0], false); err != nil {
			return err
		}
		fmt.Printf("Trusted session %s is active until %s.\n", args[0], grant.ExpiresAt.Local().Format(time.RFC3339))
		return nil
	}}
	cmd.Flags().DurationVar(&ttl, "ttl", accessctl.DefaultWorkspaceTTL, "new lifetime from now (maximum 24h)")
	return cmd
}

func trustRevokeCmd() *cobra.Command {
	return &cobra.Command{Use: "revoke TRUST_ID", Short: "Immediately revoke a trusted session", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		manager, err := openAccessManager()
		if err != nil {
			return err
		}
		if err := manager.RevokeWorkspace(args[0]); err != nil {
			return err
		}
		fmt.Printf("Revoked %s. It cannot authorize another workspace command.\n", args[0])
		return nil
	}}
}
