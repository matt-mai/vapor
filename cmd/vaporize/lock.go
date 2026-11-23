package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/catalogue"
	"github.com/matt-mai/vapor/internal/distro"
	"github.com/matt-mai/vapor/internal/distro/ubuntu/pro"
	"github.com/matt-mai/vapor/internal/locking"
	"github.com/matt-mai/vapor/internal/lockinput"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/ui"
	"github.com/matt-mai/vapor/internal/verify"
)

var httpTransport http.RoundTripper = lockTransport()

func lockTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = time.Minute
	return transport
}

func fetcherClient() *http.Client {
	// Allow a 2 GiB payload at a little over 1 MiB/s without using that
	// transfer budget to wait for headers.
	return &http.Client{Transport: httpTransport, Timeout: 30 * time.Minute}
}

type lockOptions struct {
	specPath string
	output   string
	cacheDir string
	check    bool
	diff     bool
}

func newLockCommand() *cobra.Command {
	options := &lockOptions{}
	command := &cobra.Command{
		Use:   "lock [spec]",
		Short: "Resolve and lock verified inputs",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := options.resolve(args); err != nil {
				return err
			}
			if err := options.run(cmd); err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			if options.check || options.diff {
				return nil
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), options.output)
			return err
		},
	}
	command.Flags().StringVar(&options.specPath, "spec", "", "image specification path")
	command.Flags().StringVarP(&options.output, "output", "o", "", "lock file path")
	command.Flags().StringVar(&options.cacheDir, "cache-dir", "", "verified input cache directory")
	command.Flags().BoolVar(&options.check, "check", false, "fail if the existing lock has drifted")
	command.Flags().BoolVar(&options.diff, "diff", false, "report drift without writing the lock")
	return command
}

func (options *lockOptions) resolve(args []string) error {
	if options.check && options.diff {
		return errors.New("check and diff are mutually exclusive")
	}
	if len(args) == 1 {
		if options.specPath != "" {
			return errors.New("spec path supplied twice")
		}
		options.specPath = args[0]
	}
	if options.specPath == "" {
		options.specPath = defaultSpecFile
	}
	if options.output == "" {
		options.output = defaultLockPath(options.specPath)
	}
	if resolvePath(options.output) == resolvePath(options.specPath) {
		return fmt.Errorf("output %q is the spec path; a lock cannot replace its input", options.output)
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

func (options *lockOptions) run(cmd *cobra.Command) error {
	reporter := ui.New(cmd.Context(), newReporterConfig(cmd))
	if err := options.execute(cmd, reporter); err != nil {
		return errors.Join(err, reporter.Fail(ui.Failure{Message: "lock failed"}))
	}
	return reporter.Stop()
}

const lockTarget = "lock"

// warnAll reports clock-derived diagnostics. None of them may fail a lock for its
// content; only the reporter itself can fail.
func warnAll(reporter *ui.Reporter, warnings []string) error {
	for _, warning := range warnings {
		if err := reporter.Warning(warning); err != nil {
			return err
		}
	}
	return nil
}

func (options *lockOptions) execute(cmd *cobra.Command, reporter *ui.Reporter) error {
	store, err := cache.New(options.cacheDir)
	if err != nil {
		return err
	}
	loaded, err := spec.LoadSpec(options.specPath)
	if err != nil {
		return err
	}
	provider, err := distro.Select(loaded.Distro, loaded.Release)
	if err != nil {
		return err
	}
	if warnErr := warnAll(reporter, provider.ReleaseWarnings()); warnErr != nil {
		return warnErr
	}
	release, err := store.LockGC(false)
	if err != nil {
		return err
	}
	defer release()
	evidence, err := options.collectEvidence(cmd, reporter, loaded, provider, store)
	if err != nil {
		return err
	}
	if warnErr := warnAll(reporter, evidence.Warnings); warnErr != nil {
		return warnErr
	}
	defaults, err := verify.ProviderDefaults(cmd.Context(), provider, loaded, evidence.Catalogues, evidence.Repositories, store)
	if err != nil {
		return err
	}
	assembled, err := locking.AssembleWithDefaults(loaded, provider, evidence, defaults)
	if err != nil {
		return err
	}
	policy := distro.RepositoryPolicy{Provider: provider, Repositories: loaded.Contents.Repositories}
	if err := options.auditEvidence(reporter, assembled, store, policy); err != nil {
		return err
	}
	return options.finish(cmd, reporter, assembled)
}

func (options *lockOptions) collectEvidence(cmd *cobra.Command, reporter *ui.Reporter, loaded *spec.Spec,
	provider distro.Provider, store *cache.Cache) (*locking.Evidence, error) {
	if err := reportPhase(reporter, 1, "collect inputs", ""); err != nil {
		return nil, err
	}
	evidence, err := options.collect(cmd, reporter, loaded, provider, store)
	if err != nil {
		return nil, err
	}
	details := fmt.Sprintf("%d packages, %d slices, %d artifacts", len(evidence.Packages),
		len(evidence.Slices), len(evidence.Artifacts))
	if err := reportPhase(reporter, 1, "collect inputs", details); err != nil {
		return nil, err
	}
	return evidence, reporter.CompletePhase()
}

func (options *lockOptions) auditEvidence(reporter *ui.Reporter, assembled *lock.Lockfile, store *cache.Cache,
	policy distro.RepositoryPolicy,
) error {
	if err := reportPhase(reporter, 2, "audit cache", ""); err != nil {
		return err
	}
	stats, err := locking.AuditWithPolicy(assembled, store, policy)
	if err != nil {
		return err
	}
	details := fmt.Sprintf("%d packages, %s", stats.Packages, ui.HumanBytes(stats.VerifiedBytes))
	if err := reportPhase(reporter, 2, "audit cache", details); err != nil {
		return err
	}
	return reporter.CompletePhase()
}

func (options *lockOptions) finish(cmd *cobra.Command, reporter *ui.Reporter, assembled *lock.Lockfile) error {
	if options.check || options.diff {
		if err := reportPhase(reporter, 3, "compare", ""); err != nil {
			return err
		}
		if err := options.compare(cmd, assembled); err != nil {
			return err
		}
		return reporter.CompletePhase()
	}
	if err := reportPhase(reporter, 3, "write lock", options.output); err != nil {
		return err
	}
	if err := lock.PublishLockfile(options.output, assembled); err != nil {
		return err
	}
	return reporter.CompletePhase()
}

func reportPhase(reporter *ui.Reporter, number int, title, details string) error {
	return reporter.Update(&ui.Phase{
		Target: lockTarget, Number: number, Total: 3,
		Title: title, Details: details,
	})
}

func (options *lockOptions) compare(cmd *cobra.Command, assembled *lock.Lockfile) error {
	previous, err := lock.LoadLockfile(options.output)
	if err != nil {
		return err
	}
	comparison, err := locking.Compare(previous, assembled)
	if err != nil {
		return err
	}
	if options.check {
		if !comparison.Empty() {
			return fmt.Errorf("lock drift detected:\n%s", comparison)
		}
		return nil
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), comparison)
	return err
}

func (options *lockOptions) collect(cmd *cobra.Command, reporter *ui.Reporter, loaded *spec.Spec,
	provider distro.Provider, store *cache.Cache,
) (*locking.Evidence, error) {
	request := &lockinput.Request{
		Spec: loaded, SpecDir: filepath.Dir(options.specPath), Provider: provider, Cache: store,
		Repository: repositoryFetcher,
		Artifacts:  acquire.HTTPFetcher{Client: fetcherClient()},
		Git:        catalogue.CommandGit{},
		Progress:   streamAcquired(reporter),
	}
	return lockinput.Collect(cmd.Context(), request)
}

// streamAcquired reports each archive as it lands on the step line. The number of
// packages is only known once resolution finished, so the line names the package and
// counts what it has collected; a total would be a guess until the last one.
func streamAcquired(reporter *ui.Reporter) func(acquire.Acquired, int64) {
	collected := int64(0)
	var bytes int64
	return func(acquired acquire.Acquired, size int64) {
		collected++
		bytes += size
		item := fmt.Sprintf("%s %s, %s collected", acquired.Name, acquired.Version,
			ui.HumanBytes(bytes))
		// A closed reporter, a canceled context or a full disk ends the run on its own;
		// failing the acquisition here would hide the real cause behind a display error.
		_ = reporter.Stream(item, collected, 0)
	}
}

// defaultSpecFile is the specification a command reads when none is named.
const defaultSpecFile = "image.yaml"

// resolvePath returns an absolute path with symlinks resolved when it exists. A lock
// path that does not exist yet is resolved through its directory, so an alias of the
// spec's parent directory still compares equal to the spec.
func resolvePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if resolved, evalErr := filepath.EvalSymlinks(abs); evalErr == nil {
		return resolved
	}
	if dir, dirErr := filepath.EvalSymlinks(filepath.Dir(abs)); dirErr == nil {
		return filepath.Join(dir, filepath.Base(abs))
	}
	return abs
}

func defaultLockPath(specPath string) string {
	extension := filepath.Ext(specPath)
	if extension == "" {
		return specPath + ".lock.yaml"
	}
	return strings.TrimSuffix(specPath, extension) + ".lock.yaml"
}

func defaultCacheDir() (string, error) {
	if dir := os.Getenv("VAPOR_CACHE_DIR"); dir != "" {
		return dir, nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vapor"), nil
}

func repositoryFetcher(url string, restricted bool) (lockinput.Fetcher, error) {
	var credentials pro.Credentials
	if restricted {
		loaded, err := pro.LoadDefaultCredentials(url)
		if err != nil {
			return nil, err
		}
		credentials = loaded
	}
	return pro.NewFetcher(fetcherClient(), url, credentials)
}
