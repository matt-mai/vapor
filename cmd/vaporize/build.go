package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/ui"
)

// buildOptions carries one build's flags and the inputs resolved from them.
type buildOptions struct {
	specPath        string
	lockPath        string
	cacheDir        string
	ociDir          string
	tarball         string
	push            bool
	imageOnly       bool
	jobs            int
	attestationsDir string
	signKey         string
	// phases is how many numbered steps this build will take, and exportStep and
	// pushStep are the numbers they get when the flags ask for them. A build that
	// writes nothing takes three steps, so the count it prints is the count it runs.
	phases     int
	exportStep int
	pushStep   int
	// repository and tags are filled from the specification, never from a flag.
	repository string
	tags       []string
	// spec, lock, key and documents are resolved once, so every phase describes the
	// same inputs.
	spec      *spec.Spec
	lock      *lock.Lockfile
	key       attest.SigningKey
	documents []*attest.VEXDocument
}

func newBuildCommand() *cobra.Command {
	options := &buildOptions{}
	command := &cobra.Command{
		Use:   "build [spec]",
		Short: "Build images from locked inputs",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := options.resolve(args); err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			digest, err := options.run(cmd)
			if err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), digest)
			return err
		},
	}
	command.Flags().StringVar(&options.specPath, "spec", "", "image specification path")
	command.Flags().StringVar(&options.lockPath, "lock", "", "lock file path")
	command.Flags().StringVar(&options.cacheDir, "cache-dir", "", "verified input cache directory")
	command.Flags().StringVar(&options.ociDir, "oci-dir", "", "write an OCI image layout to a new directory")
	command.Flags().StringVar(&options.tarball, "tarball", "", "write an OCI image layout tarball to a new file")
	command.Flags().BoolVar(&options.push, "push", false,
		"publish the image under the declared tags and upload its attestations")
	command.Flags().BoolVar(&options.imageOnly, "image-only", false,
		"skip registry attestations; requires --push")
	command.Flags().IntVarP(&options.jobs, "jobs", "j", 0,
		"platforms to build at once; zero builds all declared platforms at once")
	command.Flags().StringVar(&options.attestationsDir, "attestations-dir", "",
		"write each attestation statement to this directory")
	command.Flags().StringVar(&options.signKey, "sign-key", "",
		"PKCS#8 Ed25519 private key; wraps each statement in a signed DSSE envelope")
	return command
}

func (options *buildOptions) resolve(args []string) error {
	if err := options.resolvePaths(args); err != nil {
		return err
	}
	if options.jobs < 0 {
		return errors.New("jobs must not be negative")
	}
	if options.imageOnly && !options.push {
		return errors.New("--image-only requires --push")
	}
	return options.resolveSinks()
}

// resolvePaths fills the input paths from the argument, the flag or the default.
func (options *buildOptions) resolvePaths(args []string) error {
	return resolveInputPaths(&options.specPath, &options.lockPath, &options.cacheDir, args)
}

// resolveSinks refuses two outputs that would write over each other.
func (options *buildOptions) resolveSinks() error {
	for _, named := range []struct{ dir, flag string }{
		{options.ociDir, "--oci-dir"},
		{options.attestationsDir, "--attestations-dir"},
	} {
		if named.dir != "" && named.dir == options.tarball {
			return fmt.Errorf("%s and --tarball must name different destinations", named.flag)
		}
	}
	if options.ociDir != "" && options.ociDir == options.attestationsDir {
		return errors.New("--oci-dir and --attestations-dir must name different destinations")
	}
	return nil
}

// run returns the index digest of what it built.
func (options *buildOptions) run(cmd *cobra.Command) (string, error) {
	reporter := ui.New(cmd.Context(), newReporterConfig(cmd))
	summary, err := options.execute(cmd, reporter)
	if err != nil {
		return "", errors.Join(err, reporter.Fail(ui.Failure{Message: "build failed"}))
	}
	// Success both reports what was written and stops the reporter, so the last line
	// of a build names every output rather than leaving the progress line hanging.
	return summary.digest, reporter.Success(summary.ui())
}

// buildSummary is what one build produced, in the terms the report uses.
type buildSummary struct {
	digest      string
	image       string
	platforms   []string
	layers      int
	bytes       int64
	attached    []string
	destination string
}

// ui turns the build's outcome into the reporter's summary.
func (summary *buildSummary) ui() *ui.Summary {
	return &ui.Summary{
		Target: buildTarget, Image: summary.image, Platforms: summary.platforms,
		Layers: summary.layers, UncompressedBytes: summary.bytes,
		Attestations: summary.attached, Destination: summary.destination,
	}
}

const buildTarget = "build"

// plannedPhases counts the steps this build will actually take: evidence, assembly and
// attestations always, then the sinks the flags asked for. A build with no --oci-dir,
// --tarball or --push has three, and saying "[3/5]" would leave a reader waiting for
// steps that were never planned.
func (options *buildOptions) plannedPhases() {
	options.phases = 3
	if options.ociDir != "" || options.tarball != "" {
		options.exportStep = options.phases + 1
		options.phases++
	}
	if options.push {
		options.pushStep = options.phases + 1
		options.phases++
	}
}

func (options *buildOptions) execute(cmd *cobra.Command, reporter *ui.Reporter) (*buildSummary, error) {
	inputs, err := openLocked(cmd.Context(), options.specPath, options.lockPath,
		options.cacheDir, streamAssembly(reporter))
	if err != nil {
		return nil, err
	}
	options.repository = inputs.spec.Image
	options.tags = inputs.spec.Tags
	options.spec = inputs.spec
	options.lock = inputs.lock
	if options.push && len(options.tags) == 0 {
		return nil, errors.New("--push requires at least one tag in the specification")
	}
	options.plannedPhases()
	if err := checkEvidence(reporter, inputs, options.reportPhase); err != nil {
		return nil, err
	}
	if err := options.resolveAttestationInputs(inputs.lock, inputs.store); err != nil {
		return nil, err
	}
	defer options.key.Clear()
	return options.assemble(cmd, reporter, inputs.input, inputs.store)
}

// resolveAttestationInputs reads the VEX documents the lock snapshotted and the
// signing key, so both are refused before any image is assembled.
func (options *buildOptions) resolveAttestationInputs(locked *lock.Lockfile,
	store *cache.Cache,
) error {
	documents, err := importDocuments(locked, store)
	if err != nil {
		return err
	}
	options.documents = documents
	key, err := loadSigningKey(options.signKey)
	if err != nil {
		return err
	}
	options.key = key
	return nil
}

// assemble builds every declared platform, reporting each as it finishes, exports
// what the flags asked for, and returns the index digest that names the result.
func (options *buildOptions) assemble(cmd *cobra.Command, reporter *ui.Reporter,
	input *builder.Input, source oci.BlobSource,
) (*buildSummary, error) {
	platforms, err := input.Platforms()
	if err != nil {
		return nil, err
	}
	jobs := options.jobs
	if jobs == 0 {
		jobs = len(platforms)
	}
	// The step is reported before the first image is assembled, so the line is on screen
	// while the work happens. Reporting it from the completion callback instead would
	// leave a step that is only ever announced once it is already over.
	if reportErr := options.reportPhase(reporter, 2, "assemble image", ""); reportErr != nil {
		return nil, reportErr
	}
	completed := 0
	images, err := input.BuildEach(cmd.Context(), oci.DefaultCompression, jobs,
		func(platform oci.Platform) error {
			completed++
			details := fmt.Sprintf("%d/%d %s", completed, len(platforms), platform)
			return options.reportPhase(reporter, 2, "assemble image", details)
		})
	if err != nil {
		return nil, err
	}
	if completeErr := reporter.CompletePhase(); completeErr != nil {
		return nil, completeErr
	}
	layout, err := builder.Layout(images, options.tags)
	if err != nil {
		return nil, err
	}
	attached, err := options.buildAttestations(reporter, images)
	if err != nil {
		return nil, err
	}
	// The export phase starts next, so this one has to be closed or its last line stays
	// behind as an unfinished step.
	if err := reporter.CompletePhase(); err != nil {
		return nil, err
	}
	layout.Attestations = attached
	if err := options.export(cmd, reporter, &layout, source); err != nil {
		return nil, err
	}
	if err := options.publish(cmd, reporter, &layout, source); err != nil {
		return nil, err
	}
	return options.summarize(&layout, images, attached), nil
}

// publish uploads the built index when the flag asked for it. Nothing is downloaded
// here: the push is an output, and the layer bytes come from the verified cache.
func (options *buildOptions) publish(cmd *cobra.Command, reporter *ui.Reporter, layout *oci.Layout,
	source oci.BlobSource,
) error {
	if !options.push {
		return nil
	}
	details := options.repository
	if err := options.reportPhase(reporter, options.pushStep, "push image", details); err != nil {
		return err
	}
	references, err := oci.TagReferences(options.repository, options.tags)
	if err != nil {
		return err
	}
	registryOptions := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(registryHTTPS{registryTransport}),
	}
	publication := *layout
	if options.imageOnly {
		publication.Attestations = nil
	}
	pushed, err := publication.Push(cmd.Context(), source, references, registryOptions...)
	if err != nil {
		if len(pushed.References) > 0 {
			return fmt.Errorf("%w; confirmed tags for %s: %s", err, pushed.Digest, strings.Join(pushed.References, ", "))
		}
		if errors.Is(err, oci.ErrReferrersUnsupported) {
			return fmt.Errorf("%w; use --push --image-only to publish without registry attestations", err)
		}
		return err
	}
	if err := options.reportPhase(reporter, options.pushStep, "push image", pushed.Digest); err != nil {
		return err
	}
	return reporter.CompletePhase()
}

// export writes the requested sinks. A sink is reported before it is written, because
// the bytes it writes are what the bar measures; a sink that fails is left on screen as
// the step that failed, which is more use than a sink that was never mentioned.
func (options *buildOptions) export(cmd *cobra.Command, reporter *ui.Reporter, layout *oci.Layout,
	source oci.BlobSource,
) error {
	if options.ociDir != "" {
		details := options.ociDir
		if err := options.reportPhase(reporter, options.exportStep, "write OCI layout", details); err != nil {
			return err
		}
		if err := layout.WriteDirectory(cmd.Context(), options.ociDir, source); err != nil {
			return fmt.Errorf("write OCI layout: %w", err)
		}
		if err := reporter.CompletePhase(); err != nil {
			return err
		}
	}
	if options.tarball != "" {
		details := options.tarball
		if err := options.reportPhase(reporter, options.exportStep, "write tarball", details); err != nil {
			return err
		}
		if err := layout.WriteTarball(cmd.Context(), options.tarball, source,
			byteProgress(reporter)); err != nil {
			return fmt.Errorf("write tarball: %w", err)
		}
		return reporter.CompletePhase()
	}
	return nil
}

// byteProgress draws the bar a sink's own byte totals allow. The step line already
// names what is being written, so the item stays empty and only the measurement moves.
func byteProgress(reporter *ui.Reporter) func(written, total int64) {
	return func(written, total int64) {
		_ = reporter.Stream("", written, total)
	}
}

func (options *buildOptions) reportPhase(reporter *ui.Reporter, number int, title, details string) error {
	return reporter.Update(&ui.Phase{
		Target: buildTarget, Number: number,
		Total: options.phases, Title: title, Details: details,
	})
}

// summarize describes what a finished build wrote. The digest is the one a caller
// prints; everything else is what the closing line reports.
func (options *buildOptions) summarize(layout *oci.Layout, images []builder.Image,
	attached []oci.Attached,
) *buildSummary {
	summary := &buildSummary{
		digest: layout.Index.Digest, image: options.spec.Image, layers: len(images),
		destination: options.ociDir,
	}
	if summary.destination == "" {
		summary.destination = options.tarball
	}
	for position := range images {
		summary.platforms = append(summary.platforms, images[position].Platform.String())
		summary.bytes += images[position].Layer.Size
	}
	// The attached list names each format once, not once per platform, because the
	// line is about what the build produced rather than how many manifests carry it.
	seen := make(map[string]struct{}, len(attached))
	for position := range attached {
		if _, present := seen[attached[position].Kind]; present {
			continue
		}
		seen[attached[position].Kind] = struct{}{}
		summary.attached = append(summary.attached, attached[position].Kind)
	}
	return summary
}
