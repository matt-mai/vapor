package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/starter"
)

func newInitCommand() *cobra.Command {
	var options starter.Options
	command := &cobra.Command{
		Use: "init", Short: "Generate an offline Debian or Ubuntu image specification",
		Args: requireInitFlags,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := starter.Generate(options); err != nil {
				return fmt.Errorf("%w: %w", errOperation, err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Created image.yaml"); err != nil {
				return fmt.Errorf("%w: report starter creation: %w", errOperation, err)
			}
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.Distro, "distro", "", "Starter distribution (required: debian or ubuntu)")
	flags.StringVar(&options.Release, "release", "", "Starter release (required: debian trixie; ubuntu 26.04 or resolute)")
	flags.StringVar(&options.Name, "name", "", "Image name and example repository component (required)")
	flags.StringVar(&options.Dir, "dir", "", "Output directory; write image.yaml without overwrite (required)")
	return command
}

func requireInitFlags(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return err
	}
	for _, flag := range []string{"distro", "release", "name", "dir"} {
		if !cmd.Flags().Changed(flag) {
			return fmt.Errorf("required flag --%s was not provided", flag)
		}
	}
	return nil
}
