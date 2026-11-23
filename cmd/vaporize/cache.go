package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/ui"
)

type cacheOptions struct {
	cacheDir string
	output   string
	apply    bool
	minAge   time.Duration
}

func newCacheCommand() *cobra.Command {
	options := &cacheOptions{}
	command := &cobra.Command{
		Use:   "cache",
		Short: "Report and collect the verified input cache",
	}
	command.PersistentFlags().StringVar(&options.cacheDir, "cache-dir", "", "verified input cache directory")
	command.AddCommand(newCacheGCCommand(options))
	command.AddCommand(newCacheCleanCommand(options))
	command.AddCommand(newCacheBundleCommand(options))
	command.AddCommand(newCacheUnbundleCommand(options))
	return command
}

func newCacheBundleCommand(options *cacheOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "bundle <lock>",
		Short: "Write the inputs one lock references to a file",
		Long: `Write the inputs one lock references to a file.

Only the blobs that lock references are written, so the file can move a locked build to
another machine. There, extracting it into the cache with "cache unbundle" lets the
build run offline.  Nothing a bundle carries is trusted on arrival: every blob is
checked against its own digest.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return options.bundle(cmd.OutOrStdout(), args[0])
		},
	}
	command.Flags().StringVar(&options.output, "output", "", "bundle file to write")
	return command
}

func newCacheUnbundleCommand(options *cacheOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "unbundle <bundle>",
		Short: "Add the inputs of a bundle to the cache",
		Long: `Add the inputs of a bundle to the cache.

Every blob is checked against its own digest before it is stored, so a bundle cannot
introduce content the lock does not name. The build that follows reads only the cache
and stays offline.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return options.unbundle(cmd.OutOrStdout(), args[0])
		},
	}
	return command
}

func (options *cacheOptions) bundle(out io.Writer, lockPath string) error {
	if options.output == "" {
		return fmt.Errorf("%w: --output is required", errOperation)
	}
	dir, err := options.resolveDir()
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	store, err := cache.New(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	loaded, err := lock.LoadLockfile(lockPath)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	if aliasErr := refuseOutputAlias(options.output, lockPath); aliasErr != nil {
		return fmt.Errorf("%w: %v", errOperation, aliasErr)
	}
	file, err := os.CreateTemp(filepath.Dir(options.output), ".vapor-bundle-*")
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	count, bytes, bundleErr := locking.Bundle(loaded, store, file)
	closeErr := file.Close()
	if bundleErr != nil {
		return fmt.Errorf("%w: %v", errOperation, bundleErr)
	}
	if closeErr != nil {
		return fmt.Errorf("%w: %v", errOperation, closeErr)
	}
	if err := os.Rename(name, options.output); err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	_, writeErr := fmt.Fprintf(out, "wrote %s (%s) to %s\n", plural(count, "blob"), ui.HumanBytes(bytes), options.output)
	return writeErr
}

// refuseOutputAlias stops a bundle from replacing the lock it is made from. The lock is
// an input here, and the rename that publishes the bundle would leave a tar archive
// where the next build expects a lockfile.
func refuseOutputAlias(output, lockPath string) error {
	outputInfo, err := os.Stat(output)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lockInfo, err := os.Stat(lockPath)
	if err != nil {
		return err
	}
	if os.SameFile(outputInfo, lockInfo) {
		return fmt.Errorf("--output %s is the lockfile being bundled; choose another path", output)
	}
	return nil
}

func (options *cacheOptions) unbundle(out io.Writer, bundlePath string) error {
	dir, err := options.resolveDir()
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	store, err := cache.New(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	file, err := os.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	defer func() { _ = file.Close() }()
	added, present, unbundleErr := locking.Unbundle(store, file)
	if unbundleErr != nil {
		return fmt.Errorf("%w: %v", errOperation, unbundleErr)
	}
	_, writeErr := fmt.Fprintf(out, "added %s to %s, %s already present\n",
		plural(added, "blob"), dir, plural(present, "blob"))
	return writeErr
}

func newCacheGCCommand(options *cacheOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "gc [lock...]",
		Short: "Remove cached inputs that no lock references",
		Long: `Remove cached inputs that no lock references.

Without a lock argument every *.lock.yaml below the working directory is kept. Nothing
is deleted unless --apply is given, and nothing written in the last hour is touched.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return options.gc(cmd.OutOrStdout(), args)
		},
	}
	command.Flags().BoolVar(&options.apply, "apply", false, "delete the reported blobs")
	command.Flags().DurationVar(&options.minAge, "min-age", time.Hour, "protect blobs and cache writes newer than this")
	return command
}

func newCacheCleanCommand(options *cacheOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "clean",
		Short: "Remove every cached input",
		Long: `Remove every cached input.

With --apply, this deletes even inputs referenced by locks. Build cannot fetch
missing inputs. Restore the cache from a backup or run vaporize lock again.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return options.clean(cmd.OutOrStdout())
		},
	}
	command.Flags().BoolVar(&options.apply, "apply", false, "delete the cached inputs")
	return command
}

func (options *cacheOptions) gc(out io.Writer, args []string) error {
	dir, err := options.resolveDir()
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	store, err := cache.New(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	release, err := store.LockGC(true)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	defer release()
	paths, err := collectLockPaths(args)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	keep, absent, err := markedSet(paths, store)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	stats, err := store.GC(keep, cache.GCOptions{MinAge: options.minAge, Apply: options.apply})
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	if err := reportGC(out, len(paths), absent, stats, options.apply); err != nil {
		return err
	}
	if stats.Removed != 0 && !options.apply {
		if _, err := fmt.Fprintln(out, "nothing was deleted; repeat with --apply"); err != nil {
			return err
		}
	}
	return nil
}

func (options *cacheOptions) clean(out io.Writer) error {
	dir, err := options.resolveDir()
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	store, err := cache.New(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errOperation, err)
	}
	if !options.apply {
		_, writeErr := fmt.Fprintf(out, "would delete every cached input in %s; repeat with --apply\n", dir)
		return writeErr
	}
	if cleanErr := store.Clean(); cleanErr != nil {
		return fmt.Errorf("%w: %v", errOperation, cleanErr)
	}
	_, writeErr := fmt.Fprintf(out, "deleted every cached input in %s\n", dir)
	return writeErr
}

// markedSet is the digests every named lock references, and how many references the
// cache does not hold.
func markedSet(paths []string, store *cache.Cache) (map[string]struct{}, int, error) {
	keep := make(map[string]struct{})
	absent := 0
	for _, path := range paths {
		marked, missing, err := markedBlobs(path, store)
		if err != nil {
			return nil, 0, err
		}
		for digest := range marked {
			keep[digest] = struct{}{}
		}
		absent += missing
	}
	return keep, absent, nil
}

func (options *cacheOptions) resolveDir() (string, error) {
	if options.cacheDir != "" {
		return options.cacheDir, nil
	}
	return defaultCacheDir()
}

// collectLockPaths names the locks whose inputs survive. With no argument it takes every
// lock below the working directory, because the cache is shared by every project.
func collectLockPaths(args []string) ([]string, error) {
	if len(args) != 0 {
		return args, nil
	}
	found, err := walkLockPaths()
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, errors.New("no *.lock.yaml below the working directory; name a lock or use vaporize cache clean")
	}
	sort.Strings(found)
	return found, nil
}

// walkLockPaths lists the locks below the working directory, skipping hidden
// directories so a checkout's git and tool state is not walked.
func walkLockPaths() ([]string, error) {
	var found []string
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != "." && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".lock.yaml") {
			found = append(found, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find locks: %w", err)
	}
	return found, nil
}

// markedBlobs is every digest one lock references, plus the number of references the
// cache does not hold.
func markedBlobs(path string, store *cache.Cache) (map[string]struct{}, int, error) {
	loaded, err := lock.LoadLockfile(path)
	if err != nil {
		return nil, 0, err
	}
	blobs, err := locking.Blobs(loaded)
	if err != nil {
		return nil, 0, fmt.Errorf("lock %q: %w", path, err)
	}
	marked := make(map[string]struct{}, len(blobs))
	absent := 0
	for i := range blobs {
		marked[blobs[i].Digest] = struct{}{}
		if !store.Has(blobs[i].Digest) {
			absent++
		}
	}
	return marked, absent, nil
}

func reportGC(out io.Writer, locks, absent int, stats cache.GCStats, apply bool) error {
	lines := []string{fmt.Sprintf("kept %s referenced by %s", plural(stats.Kept, "cached blob"), plural(locks, "lock file"))}
	if absent != 0 {
		lines = append(lines, fmt.Sprintf("%s absent from the cache", plural(absent, "referenced blob")))
	}
	verb := "deleted with --apply"
	if apply {
		verb = "deleted"
	}
	lines = append(lines,
		fmt.Sprintf("%s %s (%s)", plural(stats.Removed, "blob"), verb, ui.HumanBytes(stats.RemovedBytes)),
		fmt.Sprintf("%s kept as recent", plural(stats.TooNew, "blob")),
	)
	if stats.Skipped != 0 {
		lines = append(lines, fmt.Sprintf("%s left alone", plural(stats.Skipped, "unrecognized cache entry")))
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}

// plural counts a thing without printing "1 blobs".
func plural(count int, thing string) string {
	if count == 1 {
		return fmt.Sprintf("1 %s", thing)
	}
	return fmt.Sprintf("%d %ss", count, thing)
}
