package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	accessctl "github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

func accessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "agents",
		Aliases: []string{"access"},
		Short:   "Review agent requests and manage revocable session leases",
		Long:    "Manage agent requests and leases without displaying or accepting secret values through MCP.",
	}
	cmd.AddCommand(accessListCmd(), accessFulfillCmd(), accessApproveCmd(), accessDenyCmd(), accessLeasesCmd(), accessRevokeCmd())
	return cmd
}

func openAccessManager() (*accessctl.Manager, error) {
	return accessctl.Open(policyProjectRoot(policyPath))
}

func accessListCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pending agent requests without secret values",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := openAccessManager()
			if err != nil {
				return err
			}
			requests, err := manager.Requests()
			if err != nil {
				return err
			}
			shown := 0
			for _, request := range requests {
				if !all && request.Status != accessctl.StatusPending {
					continue
				}
				shown++
				fmt.Printf("%s  %-9s %-9s env=%s session=%s expires=%s\n",
					request.ID, request.Kind, request.Status, request.Environment, shortAccessID(request.SessionID), request.ExpiresAt.Local().Format(time.RFC3339))
				switch request.Kind {
				case accessctl.RequestSecret:
					fmt.Printf("  alias=%s key=%s\n", request.SecretAlias, request.SecretKey)
				case accessctl.RequestLease:
					fmt.Printf("  commands=%s requested_ttl=%s\n", strings.Join(request.Commands, ","), request.RequestedTTL)
				}
				if request.Reason != "" {
					fmt.Printf("  reason=%s\n", request.Reason)
				}
			}
			if shown == 0 {
				fmt.Println("No matching agent requests.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include resolved and expired requests")
	return cmd
}

func accessFulfillCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fulfill REQUEST_ID",
		Short: "Fulfill a secret request through a masked local prompt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := openAccessManager()
			if err != nil {
				return err
			}
			request, err := manager.Request(args[0])
			if err != nil {
				return err
			}
			if request.Kind != accessctl.RequestSecret {
				return fmt.Errorf("request %s is a %s request; use access approve", request.ID, request.Kind)
			}
			if request.Status != accessctl.StatusPending {
				return fmt.Errorf("request %s is %s", request.ID, request.Status)
			}
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}
			key, storeName, ok := f.SecretBinding(request.SecretAlias)
			if !ok || key != request.SecretKey {
				return errors.New("request no longer matches the current policy; deny it and create a new request")
			}
			value, err := readSecret(false, false)
			if err != nil {
				return err
			}
			if value == "" {
				return errors.New("value cannot be empty")
			}
			if _, err := manager.FulfillSecretWith(request.ID, func(locked accessctl.Request) error {
				if f.UsesEnvironmentEntries() || f.EnvironmentSet == "active" {
					environments, err := envset.Open(policyProjectRoot(policyPath))
					if err != nil {
						return err
					}
					return environments.Put(locked.Environment, locked.SecretKey, value)
				}
				store, err := secretstore.Open(policyPath, storeName)
				if err != nil {
					return err
				}
				return store.Set(locked.SecretAlias, value)
			}); err != nil {
				return fmt.Errorf("could not atomically fulfill secret request: %w", err)
			}
			fmt.Printf("Fulfilled %s for environment %s. The value was never displayed or sent through MCP.\n", request.SecretAlias, request.Environment)
			return nil
		},
	}
}

func accessApproveCmd() *cobra.Command {
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "approve REQUEST_ID",
		Short: "Approve a pending lease request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := openAccessManager()
			if err != nil {
				return err
			}
			lease, err := manager.ApproveLease(args[0], ttl)
			if err != nil {
				return err
			}
			fmt.Printf("Approved lease %s for session %s.\n", lease.ID, shortAccessID(lease.SessionID))
			fmt.Printf("Environment: %s\nCommands: %s\nExpires: %s\n", lease.Environment, strings.Join(lease.Commands, ", "), lease.ExpiresAt.Local().Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "override requested lifetime (maximum 24h)")
	return cmd
}

func accessDenyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deny REQUEST_ID",
		Short: "Deny a pending secret or lease request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := openAccessManager()
			if err != nil {
				return err
			}
			if err := manager.Deny(args[0]); err != nil {
				return err
			}
			fmt.Printf("Denied %s.\n", args[0])
			return nil
		},
	}
}

func accessLeasesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "leases",
		Short: "List all agent leases without secret values",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := openAccessManager()
			if err != nil {
				return err
			}
			leases, err := manager.Leases("")
			if err != nil {
				return err
			}
			if len(leases) == 0 {
				fmt.Println("No agent leases.")
				return nil
			}
			now := time.Now().UTC()
			sort.Slice(leases, func(i, j int) bool { return leases[i].ExpiresAt.Before(leases[j].ExpiresAt) })
			for _, lease := range leases {
				status := "active"
				if lease.RevokedAt != nil {
					status = "revoked"
				} else if !now.Before(lease.ExpiresAt) {
					status = "expired"
				}
				fmt.Printf("%s  %-7s env=%s session=%s commands=%s expires=%s\n",
					lease.ID, status, lease.Environment, shortAccessID(lease.SessionID), strings.Join(lease.Commands, ","), lease.ExpiresAt.Local().Format(time.RFC3339))
			}
			return nil
		},
	}
}

func accessRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke LEASE_ID",
		Short: "Immediately revoke an agent lease",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := openAccessManager()
			if err != nil {
				return err
			}
			if err := manager.Revoke(args[0], ""); err != nil {
				return err
			}
			fmt.Printf("Revoked %s. It cannot authorize another command.\n", args[0])
			return nil
		},
	}
}

func policyProjectRoot(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return mustWorkingDir()
	}
	return filepath.Dir(abs)
}

func shortAccessID(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
