package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/policy"
)

// lintCmd: ironrun lint — security review of the policy file.
func lintCmd() *cobra.Command {
	var format string
	var strict bool
	c := &cobra.Command{
		Use:   "lint",
		Short: "Run security checks over the policy file",
		Long: `lint runs opinionated security checks over the policy: shell/interpreter
argv, missing ttl, secrets injected with open network egress, hardcoded
credentials in argv, and a secret shared across too many commands.

Exit is non-zero when any error-level finding is present (or any warning under
--strict), so it can gate CI. 'validate' checks that the policy is well-formed;
'lint' checks that it is safe.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}
			findings := policy.Lint(f)

			if format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(findings); err != nil {
					return err
				}
			} else {
				printFindings(findings)
			}

			worst := policy.SeverityInfo
			for _, fi := range findings {
				if fi.Severity > worst {
					worst = fi.Severity
				}
			}
			if worst >= policy.SeverityError || (strict && worst >= policy.SeverityWarn) {
				os.Exit(1)
			}
			return nil
		},
	}
	c.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	c.Flags().BoolVar(&strict, "strict", false, "Treat warnings as errors (non-zero exit)")
	return c
}

func printFindings(findings []policy.Finding) {
	if len(findings) == 0 {
		fmt.Println("No findings — policy looks good.")
		return
	}
	for _, f := range findings {
		loc := ""
		if f.CmdID != "" {
			loc = fmt.Sprintf(" [%s]", f.CmdID)
		}
		fmt.Printf("%-5s %s%s: %s\n", f.Severity.String(), f.Code, loc, f.Message)
	}
	fmt.Printf("\n%d finding(s).\n", len(findings))
}
