package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/audit"
)

// auditCmd: ironrun audit — print the local sealed-run audit trail.
func auditCmd() *cobra.Command {
	var n int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the local audit trail of sealed runs",
		Long: `Prints recent entries from the ironrun audit trail — a secret-free JSONL record
of every sealed run (command id, exit code, duration, bytes out, number of secret
values redacted, and whether the network was sealed). No secret values, resolved
environment, or raw argv are ever recorded.

Location: $IRONRUN_AUDIT_PATH, else ~/.ironrun/audit.jsonl. Disable with IRONRUN_AUDIT=off.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			path := audit.Path()
			if path == "" {
				return fmt.Errorf("no audit path available (set IRONRUN_AUDIT_PATH, or ensure HOME is set)")
			}
			f, err := os.Open(path)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintf(c.OutOrStdout(), "No audit trail yet at %s\n", path)
					return nil
				}
				return err
			}
			defer f.Close()

			var lines []string
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				lines = append(lines, sc.Text())
			}
			if err := sc.Err(); err != nil {
				return err
			}
			start := 0
			if n > 0 && len(lines) > n {
				start = len(lines) - n
			}
			for _, l := range lines[start:] {
				fmt.Fprintln(c.OutOrStdout(), l)
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&n, "tail", "n", 20, "show the last N entries (0 = all)")
	return cmd
}
