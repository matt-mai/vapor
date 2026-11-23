package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/cache"
	"github.com/matt-mai/vapor/internal/oci"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/schema/spec"
	"github.com/matt-mai/vapor/internal/ui"
)

type vexOptions struct {
	specPath  string
	lockPath  string
	cacheDir  string
	outputDir string
	signKey   string
}

func newVEXCommand() *cobra.Command {
	options := &vexOptions{}
	command := &cobra.Command{
		Use:   "vex [spec]",
		Short: "Generate OpenVEX statements for the locked claims",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := options.resolve(args); err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			paths, err := options.run(cmd)
			if err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			for _, path := range paths {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), path); err != nil {
					return err
				}
			}
			return nil
		},
	}
	command.Flags().StringVar(&options.specPath, "spec", "", "image specification path")
	command.Flags().StringVar(&options.lockPath, "lock", "", "lock file path")
	command.Flags().StringVar(&options.cacheDir, "cache-dir", "", "verified input cache directory")
	command.Flags().StringVarP(&options.outputDir, "output", "o", ".",
		"directory the VEX statements are written to")
	command.Flags().StringVar(&options.signKey, "sign-key", "",
		"PKCS#8 Ed25519 private key; wraps each statement in a signed DSSE envelope")
	return command
}

func (options *vexOptions) resolve(args []string) error {
	if err := resolveInputPaths(&options.specPath, &options.lockPath, &options.cacheDir,
		args); err != nil {
		return err
	}
	if options.outputDir == "" {
		return errors.New("output directory must not be empty")
	}
	return nil
}

func (options *vexOptions) run(cmd *cobra.Command) ([]string, error) {
	reporter := ui.New(cmd.Context(), newReporterConfig(cmd))
	paths, err := options.execute(cmd, reporter)
	if err != nil {
		return nil, errors.Join(err, reporter.Fail(ui.Failure{Message: "vex failed"}))
	}
	if err := reporter.Stop(); err != nil {
		return nil, err
	}
	return paths, nil
}

// vexPhaseTotal covers evidence, assembly and the statements themselves.
const vexPhaseTotal = 3

// execute assembles every declared platform from the verified cache and writes one
// statement per platform. It reads nothing but the spec, the lock, the cache and the
// signing key, so the claims are checked against the same tree a build would publish.
func (options *vexOptions) execute(cmd *cobra.Command, reporter *ui.Reporter) ([]string, error) {
	inputs, err := openLocked(cmd.Context(), options.specPath, options.lockPath,
		options.cacheDir, streamAssembly(reporter))
	if err != nil {
		return nil, err
	}
	if failure := checkEvidence(reporter, inputs, reportVEXPhase); failure != nil {
		return nil, failure
	}
	documents, err := importDocuments(inputs.lock, inputs.store)
	if err != nil {
		return nil, err
	}
	key, err := loadSigningKey(options.signKey)
	if err != nil {
		return nil, err
	}
	defer key.Clear()
	return options.statements(cmd, reporter, &vexRun{
		input: inputs.input, spec: inputs.spec, lock: inputs.lock,
		documents: documents, key: key,
	})
}

// vexRun is everything one invocation resolved before the first platform is built.
type vexRun struct {
	input     *builder.Input
	spec      *spec.Spec
	lock      *lock.Lockfile
	documents []*attest.VEXDocument
	key       attest.SigningKey
}

// statements renders one document per platform that has a claim. A platform with none
// is skipped: a document has to state something, and a platform whose claims were all
// about other content has nothing to say.
func (options *vexOptions) statements(cmd *cobra.Command, reporter *ui.Reporter,
	run *vexRun,
) ([]string, error) {
	platforms, err := run.input.Platforms()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(platforms))
	for position := range platforms {
		platform := platforms[position]
		details := fmt.Sprintf("%d/%d %s", position+1, len(platforms), platform)
		if err := reportVEXPhase(reporter, 2, "assemble image", details); err != nil {
			return nil, err
		}
		written, err := options.statement(cmd, reporter, run, platform)
		if err != nil {
			return nil, err
		}
		if err := reporter.CompletePhase(); err != nil {
			return nil, err
		}
		if written != "" {
			paths = append(paths, written)
		}
	}
	if len(paths) == 0 {
		return nil, errors.New("no VEX claim applies to any declared platform, " +
			"so no statement was written")
	}
	return paths, nil
}

// statement builds one platform's tree, checks its claims against it and writes the
// payload. A platform with no claim about its content produces no document, because
// an OpenVEX document has to state something.
func (options *vexOptions) statement(cmd *cobra.Command, reporter *ui.Reporter,
	run *vexRun, platform oci.Platform,
) (string, error) {
	built, err := run.input.BuildPlatform(cmd.Context(), platform, oci.DefaultCompression)
	if err != nil {
		return "", err
	}
	payload, err := run.vexPayload(&built)
	if err != nil {
		return "", err
	}
	if payload == nil {
		return "", nil
	}
	written, _, err := attest.MaybeSigned(run.key, attest.PayloadTypeVEX, payload)
	if err != nil {
		return "", err
	}
	path := filepath.Join(options.outputDir, vexFileName(run.spec.Image, platform.String()))
	if err := writeFileAtomic(path, written); err != nil {
		return "", fmt.Errorf("write VEX statement: %w", err)
	}
	if err := reportVEXPhase(reporter, 3, "write VEX statement", path); err != nil {
		return "", err
	}
	return path, nil
}

// vexPayload renders one platform's OpenVEX document, or nothing when the spec makes
// no claim about its content.
func (run *vexRun) vexPayload(built *builder.Image) ([]byte, error) {
	vexInput := &attest.VEXInput{
		Name:         run.spec.Image,
		Subject:      built.Image.ManifestDigest,
		Tree:         built.Tree,
		AbsentChecks: *run.spec.VEX.CheckAbsentPaths,
		Platform:     built.Platform.String(),
		Distro:       run.lock.Provider.Distro,
		Release:      run.lock.Provider.Release,
		Claims:       run.spec.VEX.Assertions,
		Packages:     run.lock.Packages,
		Slices:       run.lock.Slices,
		Artifacts:    run.lock.Artifacts,
	}
	for _, document := range run.documents {
		imported, err := attest.ImportClaims(vexInput, document)
		if err != nil {
			return nil, fmt.Errorf("import VEX input: %w", err)
		}
		vexInput.Imported = append(vexInput.Imported, imported...)
	}
	payload, err := attest.VEX(vexInput)
	if errors.Is(err, attest.ErrNoClaims) {
		return nil, nil
	}
	return payload, err
}

// vexFileName turns an image name and platform into one file name, so a statement is
// recognizable outside the directory it was written to.
func vexFileName(name, platform string) string {
	replacer := strings.NewReplacer("/", "-", ":", "-")
	return replacer.Replace(name) + "-" + replacer.Replace(platform) + ".openvex.json"
}

// importDocuments reads the VEX documents the lock snapshotted. Their bytes come from
// the verified cache, so an imported claim is about the file the lock recorded.
func importDocuments(locked *lock.Lockfile, store *cache.Cache) ([]*attest.VEXDocument, error) {
	var documents []*attest.VEXDocument
	for position := range locked.LocalInputs {
		record := &locked.LocalInputs[position]
		if record.Role != kindVEX {
			continue
		}
		data, err := readVEXInput(record, store)
		if err != nil {
			return nil, err
		}
		document, err := attest.DecodeVEXDocument(data)
		if err != nil {
			return nil, fmt.Errorf("VEX input %q: %w", record.Path, err)
		}
		documents = append(documents, document)
	}
	return documents, nil
}

// readVEXInput returns the locked bytes of one document. The locked size is refused
// before a blob is opened, and the bytes the store returns are the bytes it verified, so
// the decoder sees the content the lock recorded.
func readVEXInput(record *lock.LocalInput, store *cache.Cache) ([]byte, error) {
	if record.Size > attest.MaxVEXDocumentSize {
		return nil, fmt.Errorf("VEX input %q is %d bytes, more than the %d a document may have",
			record.Path, record.Size, attest.MaxVEXDocumentSize)
	}
	data, err := store.Read(record.SHA256, record.Size)
	if err != nil {
		return nil, fmt.Errorf("read VEX input %q: %w", record.Path, err)
	}
	return data, nil
}

// loadSigningKey loads the key when one was named. Without a key the statements stay
// unsigned, which is the default: a signature is an addition, never a replacement.
func loadSigningKey(path string) (attest.SigningKey, error) {
	if path == "" {
		return attest.SigningKey{}, nil
	}
	return attest.LoadSigningKey(path)
}

func reportVEXPhase(reporter *ui.Reporter, number int, title, details string) error {
	return reporter.Update(&ui.Phase{
		Target: "vex", Number: number,
		Total: vexPhaseTotal, Title: title, Details: details,
	})
}
