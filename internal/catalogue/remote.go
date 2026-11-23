package catalogue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

// MaxRemoteArchiveSize bounds the acquired Git archive before it is cached and
// decompressed. It leaves room for tar overhead above MaxTreeContentSize.
const MaxRemoteArchiveSize int64 = 512 << 20

const (
	maxGitResponseSize int64 = 1 << 20
	maxGitTreeSize     int64 = 16 << 20
	maxArchiveSize     int64 = MaxRemoteArchiveSize
)

// RemoteSource selects one branch, tag or full commit from a catalogue URL.
type RemoteSource struct {
	URL    string
	Branch *string
	Tag    *string
	Commit *string
}

// RemoteSnapshot is an immutable remote catalogue acquisition.
type RemoteSnapshot struct {
	Commit        string
	ArchiveSHA256 string
	ArchiveSize   int64
	Tree          Tree
}

// GitRunner executes Git with bounded standard output.
type GitRunner interface {
	Run(ctx context.Context, limit int64, args ...string) ([]byte, error)
}

// CommandGit runs the host Git executable. Catalogue acquisition needs Git at
// lock time; builds never call it.
type CommandGit struct{}

// ResolveRemote resolves the declared selector, fetches the exact commit and
// snapshots its archive. Commit identity does not authenticate the publisher.
func ResolveRemote(ctx context.Context, git GitRunner, source RemoteSource, store BlobStore) (RemoteSnapshot, error) {
	if ctx == nil {
		return RemoteSnapshot{}, errors.New("resolution context must not be nil")
	}
	if git == nil {
		return RemoteSnapshot{}, errors.New("git runner must not be nil")
	}
	if store == nil {
		return RemoteSnapshot{}, errors.New("blob store must not be nil")
	}
	if err := validateRemoteSource(source); err != nil {
		return RemoteSnapshot{}, err
	}
	commit, err := resolveRemoteCommit(ctx, git, source)
	if err != nil {
		return RemoteSnapshot{}, err
	}
	archive, err := fetchRemoteArchive(ctx, git, source.URL, commit)
	if err != nil {
		return RemoteSnapshot{}, err
	}
	tree, err := SnapshotArchive(archive, store)
	if err != nil {
		return RemoteSnapshot{}, err
	}
	sum := sha256.Sum256(archive)
	return RemoteSnapshot{
		Commit:        commit,
		ArchiveSHA256: hex.EncodeToString(sum[:]),
		ArchiveSize:   int64(len(archive)),
		Tree:          tree,
	}, nil
}

func validateRemoteSource(source RemoteSource) error {
	if err := base.ValidateInputURL(source.URL, false); err != nil {
		return err
	}
	selectors := 0
	for _, selector := range []*string{source.Branch, source.Tag, source.Commit} {
		if selector != nil {
			selectors++
		}
	}
	if selectors != 1 {
		return errors.New("remote catalogue requires exactly one branch, tag or commit")
	}
	if source.Commit != nil {
		if !isCommitHash(*source.Commit) {
			return errors.New("catalogue commit must be a full lowercase 40- or 64-hex object ID")
		}
		return nil
	}
	ref := source.Tag
	if ref == nil {
		ref = source.Branch
	}
	if err := contents.ValidateGitRef(*ref); err != nil {
		return err
	}
	return nil
}

func resolveRemoteCommit(ctx context.Context, git GitRunner, source RemoteSource) (string, error) {
	if source.Commit != nil {
		return *source.Commit, nil
	}
	ref, tag := remoteRef(source)
	args := []string{"ls-remote", source.URL, ref}
	if tag {
		args = append(args, ref+"^{}")
	}
	output, err := git.Run(ctx, maxGitResponseSize, args...)
	if err != nil {
		return "", errors.New("catalogue ref lookup failed")
	}
	commit, err := parseRemoteRefs(output, ref, tag)
	if err != nil {
		return "", err
	}
	return commit, nil
}

func remoteRef(source RemoteSource) (string, bool) {
	if source.Tag != nil {
		return "refs/tags/" + *source.Tag, true
	}
	return "refs/heads/" + *source.Branch, false
}

func parseRemoteRefs(output []byte, ref string, tag bool) (string, error) {
	peeled := ""
	direct := ""
	for line := range strings.Lines(string(output)) {
		if err := recordRemoteRef(strings.TrimSuffix(line, "\n"), ref, &direct, &peeled); err != nil {
			return "", err
		}
	}
	if tag && peeled != "" {
		return peeled, nil
	}
	if direct == "" {
		return "", errors.New("catalogue selector was not found")
	}
	return direct, nil
}

func recordRemoteRef(line, ref string, direct, peeled *string) error {
	hash, name, ok := strings.Cut(line, "\t")
	if !ok || !isCommitHash(hash) {
		return errors.New("catalogue ref lookup returned malformed data")
	}
	switch name {
	case ref:
		if *direct != "" {
			return errors.New("catalogue ref lookup returned duplicate refs")
		}
		*direct = hash
	case ref + "^{}":
		if *peeled != "" {
			return errors.New("catalogue ref lookup returned duplicate peeled refs")
		}
		*peeled = hash
	}
	return nil
}

func fetchRemoteArchive(ctx context.Context, git GitRunner, url, commit string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "vapor-catalogue-")
	if err != nil {
		return nil, errors.New("create catalogue acquisition directory failed")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	objectFormat := "sha1"
	if len(commit) == 64 {
		objectFormat = "sha256"
	}
	if _, runErr := git.Run(ctx, maxGitResponseSize, "init", "--bare", "--quiet",
		"--object-format="+objectFormat, dir); runErr != nil {
		return nil, errors.New("initialize catalogue repository failed")
	}
	if _, runErr := git.Run(ctx, maxGitResponseSize, "-C", dir, "fetch", "--quiet", "--depth=1", "--no-tags", url,
		commit); runErr != nil {
		return nil, errors.New("catalogue commit is unavailable")
	}
	output, err := git.Run(ctx, maxGitResponseSize, "-C", dir, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return nil, errors.New("catalogue commit is unavailable")
	}
	if strings.TrimSpace(string(output)) != commit {
		return nil, errors.New("catalogue commit did not resolve to the requested object")
	}
	if inspectErr := inspectRemoteTree(ctx, git, dir, commit); inspectErr != nil {
		return nil, inspectErr
	}
	archive, err := git.Run(ctx, maxArchiveSize, "-C", dir, "archive", "--format=tar.gz", commit)
	if err != nil {
		return nil, errors.New("catalogue archive acquisition failed")
	}
	return archive, nil
}

func inspectRemoteTree(ctx context.Context, git GitRunner, dir, commit string) error {
	output, err := git.Run(ctx, maxGitTreeSize, "-C", dir, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return errors.New("catalogue tree inspection failed")
	}
	return validateRemoteTree(output)
}

func validateRemoteTree(output []byte) error {
	for record := range bytes.SplitSeq(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		metadata, _, found := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(metadata)
		if !found || len(fields) != 3 {
			return errors.New("catalogue tree inspection returned malformed data")
		}
		if string(fields[0]) == "160000" || string(fields[1]) == "commit" {
			return errors.New("catalogue tree contains a gitlink")
		}
	}
	return nil
}

func isCommitHash(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

// Run executes Git without a shell and bounds its standard output.
func (CommandGit) Run(ctx context.Context, limit int64, args ...string) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("git output limit must be positive")
	}
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // No shell; arguments are validated before use.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	cmd.Stderr = io.Discard
	output := &limitedBuffer{limit: limit}
	cmd.Stdout = output
	err := cmd.Run()
	if output.overflow {
		return nil, errGitOutputTooLarge
	}
	if err != nil {
		return nil, errors.New("git command failed")
	}
	return output.Bytes(), nil
}

var errGitOutputTooLarge = errors.New("git output exceeded the configured limit")

type limitedBuffer struct {
	data     bytes.Buffer
	limit    int64
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if int64(b.data.Len())+int64(len(p)) > b.limit {
		b.overflow = true
		return 0, fmt.Errorf("git output exceeds %d bytes", b.limit)
	}
	return b.data.Write(p)
}

func (b *limitedBuffer) Bytes() []byte {
	return b.data.Bytes()
}
