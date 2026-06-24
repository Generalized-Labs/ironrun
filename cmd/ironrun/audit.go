package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/policy"
)

// auditCmd: ironrun audit — inspect the tamper-evident audit log.
func auditCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the tamper-evident audit log",
	}
	c.AddCommand(auditVerifyCmd())
	return c
}

func auditVerifyCmd() *cobra.Command {
	var logPath string
	c := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit log hash chain is intact",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := logPath
			if path == "" {
				// Resolve via env > policy > default; loading the policy is best-effort.
				policyField := ""
				if f, err := policy.Load(policyPath); err == nil {
					policyField = f.AuditLog
				}
				path = audit.ResolvePath(policyField)
			}
			if path == "" {
				return fmt.Errorf("auditing is disabled; pass --log <path> to verify a specific file")
			}
			broken, err := audit.Verify(path)
			if err != nil {
				return err
			}
			if broken == -1 {
				fmt.Printf("audit log intact: %s\n", path)
				return nil
			}
			fmt.Fprintf(os.Stderr, "TAMPER DETECTED at line %d in %s\n", broken, path)
			os.Exit(1)
			return nil
		},
	}
	c.Flags().StringVar(&logPath, "log", "", "Path to the audit log (default: resolved from env/policy)")
	return c
}
