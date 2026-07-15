package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/localapi"
	"github.com/generalized-labs/ironrun/internal/policy"
)

func serveCmd() *cobra.Command {
	var socketPath string
	cmd := &cobra.Command{
		Use:     "api",
		Aliases: []string{"serve"},
		Short:   "Serve the value-blind local API over an owner-only Unix socket",
		Long: `Expose status, environment metadata, access state, revocation, and sealed
execution to local curl clients. The API has no plaintext secret endpoint and
refuses unknown JSON fields. The socket is created with owner-only permissions.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}
			root := policyProjectRoot(policyPath)
			if socketPath == "" {
				socketPath = filepath.Join(root, ".ironrun", "ironrun.sock")
			} else if !filepath.IsAbs(socketPath) {
				socketPath, err = filepath.Abs(socketPath)
				if err != nil {
					return err
				}
			}
			fmt.Printf("Ironrun local API: %s\n", socketPath)
			fmt.Printf("Status: curl --unix-socket %q http://localhost/v1/status\n", socketPath)
			fmt.Println("No endpoint accepts plaintext secret values.")
			return localapi.Serve(context.Background(), f, policyPath, root, socketPath)
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path (default: .ironrun/ironrun.sock beside the policy)")
	return cmd
}
