package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/capsule"
)

func capsuleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capsule",
		Short: "Create chat-safe, one-use encrypted secret capsules",
		Long: `A capsule is encrypted before it enters chat and is bound to one pending
secret request, project, MCP session, and short expiry. The agent receives only
ciphertext and can claim it once; it never receives the plaintext value.`,
	}
	cmd.AddCommand(capsuleCreateCmd())
	return cmd
}

func capsuleCreateCmd() *cobra.Command {
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "create REQUEST_ID",
		Short: "Read a secret through a masked prompt and print paste-safe ciphertext",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requests, err := openAccessManager()
			if err != nil {
				return err
			}
			request, err := requests.Request(args[0])
			if err != nil {
				return err
			}
			if request.Kind != access.RequestSecret || request.Status != access.StatusPending {
				return fmt.Errorf("request %s is not a pending secret request", request.ID)
			}
			value, err := readSecret(false, false)
			if err != nil {
				return err
			}
			if value == "" {
				return fmt.Errorf("value cannot be empty")
			}
			manager, err := capsule.Open(policyProjectRoot(policyPath))
			if err != nil {
				return err
			}
			sealed, err := manager.Seal(capsule.Payload{
				RequestID: request.ID, SessionID: request.SessionID,
				Environment: request.Environment, SecretAlias: request.SecretAlias,
				SecretKey: request.SecretKey, Value: value,
			}, ttl)
			if err != nil {
				return err
			}
			fmt.Println(sealed)
			return nil
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", capsule.DefaultTTL, "capsule lifetime (maximum 10m)")
	return cmd
}
