package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/schema/lock"
)

func newInspectCommand() *cobra.Command {
	var lockPath string
	command := &cobra.Command{
		Use:   "inspect [lock]",
		Short: "Inspect recorded lock identities and evidence",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if lockPath != "" {
					return fmt.Errorf("%w: lock path supplied twice", errOperation)
				}
				lockPath = args[0]
			}
			if lockPath == "" {
				lockPath = "image.lock.yaml"
			}
			loaded, err := lock.LoadLockfile(lockPath)
			if err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			data, err := loaded.CanonicalYAML()
			if err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
	command.Flags().StringVar(&lockPath, "lock", "", "lock file path")
	return command
}
