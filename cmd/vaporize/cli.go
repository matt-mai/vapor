// Command vaporize implements the vapor command-line interface.
package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var errOperation = errors.New("operation failed")

func run(args []string, stdout, stderr io.Writer) int {
	out, diagnostics := &outputWriter{Writer: stdout}, &outputWriter{Writer: stderr}
	root := newRoot()
	root.SetOut(out)
	root.SetErr(diagnostics)
	root.SetArgs(append([]string{}, args...))
	err := root.Execute()
	if out.err != nil || diagnostics.err != nil {
		return 1
	}
	if err == nil {
		return 0
	}
	code := 2
	if errors.Is(err, errOperation) {
		code = 1
	}
	if _, writeErr := fmt.Fprintln(diagnostics, "vaporize:", err); writeErr != nil {
		return 1
	}
	return code
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use: "vaporize", Short: "Generate, lock and build deterministic images",
		SilenceErrors: true, SilenceUsage: true,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("a command is required; use vaporize --help")
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	// These apply to every command that reports progress, so they are persistent rather
	// than repeated on each one. Neither changes what a command does, only what it says.
	root.PersistentFlags().Bool("quiet", false,
		"report only step outcomes, without naming each item as it is collected")
	root.PersistentFlags().Bool("no-progress", false,
		"draw no spinner or progress bar; report each step as a line")
	root.AddCommand(newInitCommand())
	root.AddCommand(newLockCommand())
	root.AddCommand(newInspectCommand())
	root.AddCommand(newCacheCommand())
	root.AddCommand(newSlicesCommand())
	root.AddCommand(newBuildCommand())
	root.AddCommand(newOutdatedCommand())
	root.AddCommand(newVEXCommand())
	root.AddCommand(newVersionCommand())
	root.SetHelpCommand(helpCommand(root))
	return root
}

// version is stamped by the release pipeline, because a binary built from a checkout has
// no module version to report.
var version string

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print the version",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), toolchainVersion())
			return err
		},
	}
}

func helpCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use: "help [command]", Short: "Help about any command",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			command, remaining, err := root.Find(args)
			if err != nil {
				return fmt.Errorf("find help command: %w", err)
			}
			if len(remaining) != 0 {
				return fmt.Errorf("unknown help command %q", remaining[0])
			}
			return command.Help()
		},
	}
}

// Cobra's help callback does not return write errors to Execute.
type outputWriter struct {
	io.Writer
	err error
}

func (w *outputWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if w.err == nil {
		w.err = err
	}
	return n, err
}
