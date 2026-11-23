package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/lockinput"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/ui"
)

type outdatedOptions struct {
	lockPath string
	specPath string
	cacheDir string
}

func newOutdatedCommand() *cobra.Command {
	options := &outdatedOptions{}
	command := &cobra.Command{
		Use:   "outdated [lock]",
		Short: "Report locked packages a repository now offers a newer version of",
		Long: "Reports the packages and slices a locked image contains that the repositories\n" +
			"now offer a newer version of. Only repository metadata is fetched, so the\n" +
			"command downloads no package and writes no new cache entry.\n\n" +
			"It exits with 0 when nothing is newer and 1 when something is.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := options.resolve(args); err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			updates, err := options.run(cmd)
			if err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			return reportUpdates(cmd, updates)
		},
	}
	command.Flags().StringVar(&options.lockPath, "lock", "", "lock file path")
	command.Flags().StringVar(&options.specPath, "spec", "", "image specification path")
	command.Flags().StringVar(&options.cacheDir, "cache-dir", "", "verified input cache directory")
	return command
}

func (options *outdatedOptions) resolve(args []string) error {
	if len(args) == 1 {
		if options.lockPath != "" {
			return errors.New("lock path supplied twice")
		}
		options.lockPath = args[0]
	}
	if options.lockPath == "" {
		options.lockPath = "image.lock.yaml"
	}
	// The specification lives beside its lock unless the caller says otherwise.
	if options.specPath == "" {
		options.specPath = defaultLockOrigin(options.lockPath)
	}
	if options.cacheDir == "" {
		dir, err := defaultCacheDir()
		if err != nil {
			return err
		}
		options.cacheDir = dir
	}
	return nil
}

// defaultLockOrigin returns the specification path a lock beside it was made from.
func defaultLockOrigin(lockPath string) string {
	base := filepath.Base(lockPath)
	name, ok := strings.CutSuffix(base, ".lock.yaml")
	if !ok {
		return defaultSpecFile
	}
	return filepath.Join(filepath.Dir(lockPath), name+".yaml")
}

func (options *outdatedOptions) run(cmd *cobra.Command) ([]locking.Update, error) {
	store, err := cache.New(options.cacheDir)
	if err != nil {
		return nil, err
	}
	locked, err := lock.LoadLockfile(options.lockPath)
	if err != nil {
		return nil, err
	}
	loaded, err := spec.LoadSpec(options.specPath)
	if err != nil {
		return nil, err
	}
	provider, err := distro.Select(loaded.Distro, loaded.Release)
	if err != nil {
		return nil, err
	}
	// The lock must describe this specification, or the answer is about a different
	// image than the one the caller asked about.
	expected, err := loaded.SpecDigestForRelease(provider.Release())
	if err != nil {
		return nil, err
	}
	if locked.SpecDigest != expected {
		return nil, fmt.Errorf("lock does not describe %q; run vaporize lock first", options.specPath)
	}
	release, err := store.LockGC(false)
	if err != nil {
		return nil, err
	}
	defer release()
	reporter := ui.New(cmd.Context(), newReporterConfig(cmd))
	evidence, err := lockinput.ResolveSelection(cmd.Context(), &lockinput.Request{
		Spec: loaded, SpecDir: filepath.Dir(options.specPath), Provider: provider, Cache: store,
		Repository: repositoryFetcher,
		Artifacts:  acquire.HTTPFetcher{Client: fetcherClient()},
		Git:        catalogue.CommandGit{},
	})
	if err != nil {
		return nil, errors.Join(err, reporter.Fail(ui.Failure{Message: "outdated failed"}))
	}
	if err := reporter.Stop(); err != nil {
		return nil, err
	}
	return locking.Updates(locked, evidence.Packages, evidence.Slices)
}

// reportUpdates prints one line per update and fails when there is one, so a pipeline
// can branch on the exit code alone.
func reportUpdates(cmd *cobra.Command, updates []locking.Update) error {
	out := cmd.OutOrStdout()
	if len(updates) == 0 {
		_, err := fmt.Fprintln(out, "no updates")
		return err
	}
	for _, update := range updates {
		if _, err := fmt.Fprintln(out, update); err != nil {
			return err
		}
	}
	return fmt.Errorf("%w: %d update(s) available", errOperation, len(updates))
}
