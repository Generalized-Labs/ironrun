package main

import (
	"github.com/spf13/cobra"

	irontui "github.com/generalized-labs/ironrun/internal/tui"
)

func tuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the Ironrun local vault and agent-access control room",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(policyPath)
		},
	}
}

func runTUI(path string) error { return irontui.Run(path) }
