package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/shellguard"
)

// shellCmd: ironrun shell — shell history hygiene helpers.
func shellCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "shell",
		Short: "Shell history hygiene: guard snippets for your rc files",
	}
	c.AddCommand(shellInitCmd())
	return c
}

// shellInitCmd: ironrun shell init — prints (or installs) an idempotent rc
// snippet that warns loudly when the user types `export <VAULT_ALIAS>=<literal>`
// or a generic `export SECRET|TOKEN|KEY=<long literal>`.
func shellInitCmd() *cobra.Command {
	var shellFlag string
	var install bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Print/install an rc snippet guarding against export-to-history",
		Long: `Prints an idempotent shell snippet (bash, zsh, or fish) that:

  • sets history-ignoring options (HISTCONTROL=ignoreboth for bash,
    HIST_IGNORE_SPACE for zsh)
  • installs a pre-execution guard that WARNS LOUDLY when a command line
    looks like 'export NAME=<literal>' where NAME is one of your vault
    aliases or a secret-shaped name (SECRET/TOKEN/KEY/PASSWORD/CREDENTIAL)

The guard warns — it cannot portably stop the command, so press Ctrl-C when
you see it. It never prints or strips values.

With --install the snippet is appended to your rc file (default per shell);
re-running is a no-op thanks to marker comments. Otherwise the snippet is
printed to stdout for review.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			var sh shellguard.Shell
			if shellFlag != "" {
				var err error
				sh, err = shellguard.ParseShell(shellFlag)
				if err != nil {
					return err
				}
			} else {
				sh = shellguard.DetectShell()
			}
			var aliases []string
			if secrets, err := loadActiveSecrets(); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "ironrun: warning: %v — snippet will use generic patterns only\n", err)
			} else {
				for _, s := range secrets {
					aliases = append(aliases, s.Alias)
				}
			}
			snippet := shellguard.Snippet(sh, aliases)
			if !install {
				fmt.Fprint(out, snippet)
				fmt.Fprintf(out, "\n# Re-run with --install to append this to %s\n", shellguard.DefaultRCPath(sh))
				return nil
			}
			rc := shellguard.DefaultRCPath(sh)
			wrote, err := shellguard.Install(rc, snippet)
			if err != nil {
				return err
			}
			if wrote {
				fmt.Fprintf(out, "installed shell-guard snippet into %s\n", rc)
			} else {
				fmt.Fprintf(out, "shell-guard snippet already present in %s (no-op)\n", rc)
			}
			return nil
		},
	}
	c.Flags().StringVar(&shellFlag, "shell", "", "bash, zsh, or fish (default: detected from $SHELL)")
	c.Flags().BoolVar(&install, "install", false, "append the snippet to the shell's rc file")
	return c
}
