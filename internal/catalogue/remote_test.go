package catalogue

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/cache"
)

func TestResolveRemoteBranchAndAnnotatedTag(t *testing.T) {
	fixture := newGitFixture(t)
	first := fixture.commit(t, "format: v3\n")
	fixture.tagAnnotated(t, "v1.0", first)
	second := fixture.commit(t, "format: v3\n# changed\n")
	fixture.push(t)

	store := newTestCache(t)
	branch := "main"
	branchSnapshot, err := ResolveRemote(context.Background(), CommandGit{}, RemoteSource{URL: fixture.url, Branch: &branch}, store)
	if err != nil {
		t.Fatal(err)
	}
	if branchSnapshot.Commit != second {
		t.Fatalf("branch commit = %q, want %q", branchSnapshot.Commit, second)
	}
	if branchSnapshot.ArchiveSHA256 == "" || branchSnapshot.ArchiveSize == 0 {
		t.Fatalf("archive evidence missing: %+v", branchSnapshot)
	}
	if digest, digestErr := branchSnapshot.Tree.Digest(); digestErr != nil || digest == "" {
		t.Fatalf("tree digest = %q, %v", digest, digestErr)
	}

	tag := "v1.0"
	tagSnapshot, err := ResolveRemote(context.Background(), CommandGit{}, RemoteSource{URL: fixture.url, Tag: &tag}, store)
	if err != nil {
		t.Fatal(err)
	}
	if tagSnapshot.Commit != first {
		t.Fatalf("tag commit = %q, want peeled commit %q", tagSnapshot.Commit, first)
	}
	if tagObject := fixture.revParse(t, "v1.0"); tagSnapshot.Commit == tagObject {
		t.Fatal("annotated tag object was not peeled to its commit")
	}
}

func TestResolveRemoteDirectCommitBypassesRefLookup(t *testing.T) {
	fixture := newGitFixture(t)
	first := fixture.commit(t, "format: v3\n")
	fixture.tagAnnotated(t, "v1.0", first)
	fixture.commit(t, "format: v3\n# changed\n")
	fixture.push(t)

	runner := &recordingGit{inner: CommandGit{}}
	snapshot, err := ResolveRemote(context.Background(), runner, RemoteSource{URL: fixture.url, Commit: &first}, newTestCache(t))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Commit != first {
		t.Fatalf("commit = %q, want %q", snapshot.Commit, first)
	}
	for _, call := range runner.calls {
		if len(call) > 0 && call[0] == "ls-remote" {
			t.Fatal("direct commit performed a moving-ref lookup")
		}
	}
}

func TestResolveRemoteMovedBranch(t *testing.T) {
	fixture := newGitFixture(t)
	first := fixture.commit(t, "format: v3\n")
	fixture.push(t)
	branch := "main"
	before, err := ResolveRemote(context.Background(), CommandGit{}, RemoteSource{URL: fixture.url, Branch: &branch}, newTestCache(t))
	if err != nil {
		t.Fatal(err)
	}
	if before.Commit != first {
		t.Fatalf("first resolution = %q, want %q", before.Commit, first)
	}

	second := fixture.commit(t, "format: v3\n# moved\n")
	fixture.push(t)
	after, err := ResolveRemote(context.Background(), CommandGit{}, RemoteSource{URL: fixture.url, Branch: &branch}, newTestCache(t))
	if err != nil {
		t.Fatal(err)
	}
	if after.Commit != second {
		t.Fatalf("second resolution = %q, want %q", after.Commit, second)
	}
}

func TestResolveRemoteUnavailableCommit(t *testing.T) {
	fixture := newGitFixture(t)
	fixture.commit(t, "format: v3\n")
	fixture.push(t)
	missing := strings.Repeat("a", 40)
	_, err := ResolveRemote(context.Background(), CommandGit{}, RemoteSource{URL: fixture.url, Commit: &missing}, newTestCache(t))
	if err == nil || err.Error() != "catalogue commit is unavailable" {
		t.Fatalf("unavailable commit: %v", err)
	}
	if strings.Contains(err.Error(), fixture.url) {
		t.Fatal("error exposed the catalogue URL")
	}
}

func TestResolveRemoteValidatesSource(t *testing.T) {
	ctx := context.Background()
	store := newTestCache(t)
	branch, tag := "main", "v1"
	tests := []struct {
		name   string
		source RemoteSource
	}{
		{"empty URL", RemoteSource{Branch: &branch}},
		{"no selector", RemoteSource{URL: "https://example.com/catalogue"}},
		{"two selectors", RemoteSource{URL: "https://example.com/catalogue", Branch: &branch, Tag: &tag}},
		{"invalid ref", RemoteSource{URL: "https://example.com/catalogue", Branch: new("HEAD")}},
		{"short commit", RemoteSource{URL: "https://example.com/catalogue", Commit: new("abc123")}},
		{"uppercase commit", RemoteSource{URL: "https://example.com/catalogue", Commit: new(strings.Repeat("A", 40))}},
		{"credentials", RemoteSource{URL: "https://user:pass@example.com/catalogue", Branch: &branch}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ResolveRemote(ctx, CommandGit{}, test.source, store); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if _, err := ResolveRemote(ctx, CommandGit{}, RemoteSource{URL: "https://example.com/catalogue", Branch: &branch}, nil); err == nil {
		t.Fatal("expected nil store error")
	}
	if _, err := ResolveRemote(ctx, nil, RemoteSource{URL: "https://example.com/catalogue", Branch: &branch}, store); err == nil {
		t.Fatal("expected nil git runner error")
	}
	var nilContext context.Context
	if _, err := ResolveRemote(nilContext, CommandGit{}, RemoteSource{URL: "https://example.com/catalogue", Branch: &branch}, store); err == nil {
		t.Fatal("expected nil context error")
	}
}

func TestResolveRemoteMalformedRefResponse(t *testing.T) {
	branch := "main"
	_, err := ResolveRemote(context.Background(), stubGit{output: []byte("not a ref advertisement\n")}, RemoteSource{URL: "https://example.com/catalogue", Branch: &branch}, newTestCache(t))
	if err == nil || err.Error() != "catalogue ref lookup returned malformed data" {
		t.Fatalf("malformed response: %v", err)
	}
}

func TestResolveRemoteRedactsGitFailure(t *testing.T) {
	branch := "main"
	secret := errors.New("git failed at /secret/path")
	_, err := ResolveRemote(context.Background(), stubGit{err: secret}, RemoteSource{URL: "https://example.com/catalogue", Branch: &branch}, newTestCache(t))
	if err == nil || err.Error() != "catalogue ref lookup failed" {
		t.Fatalf("git failure: %v", err)
	}
}

func TestParseRemoteRefs(t *testing.T) {
	first, second := strings.Repeat("1", 40), strings.Repeat("2", 40)
	tests := []struct {
		name    string
		output  string
		ref     string
		tag     bool
		want    string
		wantErr bool
	}{
		{"branch", first + "\trefs/heads/main\n", "refs/heads/main", false, first, false},
		{"lightweight tag", first + "\trefs/tags/v1\n", "refs/tags/v1", true, first, false},
		{"annotated tag", first + "\trefs/tags/v1\n" + second + "\trefs/tags/v1^{}\n", "refs/tags/v1", true, second, false},
		{"missing", first + "\trefs/heads/other\n", "refs/heads/main", false, "", true},
		{"malformed line", "not-a-ref\n", "refs/heads/main", false, "", true},
		{"uppercase hash", strings.Repeat("A", 40) + "\trefs/heads/main\n", "refs/heads/main", false, "", true},
		{"duplicate", first + "\trefs/heads/main\n" + second + "\trefs/heads/main\n", "refs/heads/main", false, "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseRemoteRefs([]byte(test.output), test.ref, test.tag)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("got %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestFetchRemoteArchiveSelectsObjectFormat(t *testing.T) {
	for _, test := range []struct {
		name   string
		commit string
		format string
	}{
		{"sha1", strings.Repeat("a", 40), "sha1"},
		{"sha256", strings.Repeat("a", 64), "sha256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var init []string
			runner := funcGit(func(_ context.Context, _ int64, args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				switch {
				case args[0] == "init":
					init = append([]string(nil), args...)
				case strings.Contains(command, "rev-parse"):
					return []byte(test.commit + "\n"), nil
				}
				return nil, nil
			})
			if _, err := fetchRemoteArchive(context.Background(), runner, "https://example.com/catalogue", test.commit); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(init, " "); !strings.Contains(got, "--object-format="+test.format) {
				t.Fatalf("init = %q, want object format %s", got, test.format)
			}
		})
	}
}

func TestResolveRemoteIgnoresAmbientObjectFormat(t *testing.T) {
	fixture := newGitFixture(t)
	fixture.commit(t, "format: v3\n")
	fixture.push(t)
	t.Setenv("GIT_DEFAULT_HASH", "sha256")
	branch := "main"
	if _, err := ResolveRemote(context.Background(), CommandGit{}, RemoteSource{URL: fixture.url, Branch: &branch}, newTestCache(t)); err != nil {
		t.Fatal(err)
	}
}

func TestFetchRemoteArchiveRejectsGitlink(t *testing.T) {
	commit := strings.Repeat("a", 40)
	submodule := strings.Repeat("b", 40)
	runner := funcGit(func(_ context.Context, _ int64, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		switch {
		case strings.Contains(command, "archive"):
			t.Fatal("archive ran after a gitlink was found")
		case strings.Contains(command, "ls-tree"):
			return []byte("160000 commit " + submodule + "\tsub\x00"), nil
		case strings.Contains(command, "rev-parse"):
			return []byte(commit + "\n"), nil
		}
		return nil, nil
	})
	_, err := fetchRemoteArchive(context.Background(), runner, "https://example.com/catalogue", commit)
	if err == nil || err.Error() != "catalogue tree contains a gitlink" {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateRemoteTreeRejectsMalformedData(t *testing.T) {
	if err := validateRemoteTree([]byte("garbage\x00")); err == nil {
		t.Fatal("malformed tree accepted")
	}
}

func TestCommandGitBoundsOutput(t *testing.T) {
	_, err := (CommandGit{}).Run(context.Background(), 8, "--version")
	if !errors.Is(err, errGitOutputTooLarge) {
		t.Fatalf("bounded output error = %v", err)
	}
}

type funcGit func(context.Context, int64, ...string) ([]byte, error)

func (f funcGit) Run(ctx context.Context, limit int64, args ...string) ([]byte, error) {
	return f(ctx, limit, args...)
}

type stubGit struct {
	output []byte
	err    error
}

func (g stubGit) Run(context.Context, int64, ...string) ([]byte, error) {
	return g.output, g.err
}

type recordingGit struct {
	inner GitRunner
	calls [][]string
}

func (g *recordingGit) Run(ctx context.Context, limit int64, args ...string) ([]byte, error) {
	g.calls = append(g.calls, append([]string(nil), args...))
	return g.inner.Run(ctx, limit, args...)
}

type gitFixture struct {
	url  string
	work string
}

func newGitFixture(t *testing.T) *gitFixture {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal("git executable is required for catalogue acquisition tests")
	}
	root := t.TempDir()
	bare := filepath.Join(root, "catalogue.git")
	fixture := &gitFixture{
		url:  "",
		work: filepath.Join(t.TempDir(), "work"),
	}
	runGit(t, "", "init", "--bare", "--quiet", bare)
	runGit(t, "", "init", "--quiet", "-b", "main", fixture.work)
	runGit(t, fixture.work, "config", "user.name", "Vapor Test")
	runGit(t, fixture.work, "config", "user.email", "vapor@example.invalid")
	runGit(t, fixture.work, "remote", "add", "origin", bare)

	handler := &cgi.Handler{
		Path:   gitPath,
		Args:   []string{"http-backend"},
		Stderr: io.Discard,
		Logger: log.New(io.Discard, "", 0),
		Env: []string{
			"GIT_PROJECT_ROOT=" + root,
			"GIT_HTTP_EXPORT_ALL=1",
		},
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	fixture.url = server.URL + "/catalogue.git"
	return fixture
}

func (f *gitFixture) commit(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(f.work, "chisel.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, f.work, "add", "chisel.yaml")
	runGit(t, f.work, "commit", "--quiet", "-m", "update catalogue")
	return f.revParse(t, "HEAD")
}

func (f *gitFixture) tagAnnotated(t *testing.T, name, commit string) {
	t.Helper()
	runGit(t, f.work, "tag", "-a", name, "-m", "catalogue release", commit)
}

func (f *gitFixture) push(t *testing.T) {
	t.Helper()
	runGit(t, f.work, "push", "--quiet", "--tags", "origin", "main")
}

func (f *gitFixture) revParse(t *testing.T, ref string) string {
	t.Helper()
	output := runGit(t, f.work, "rev-parse", ref)
	return strings.TrimSpace(output)
}

func newTestCache(t *testing.T) *cache.Cache {
	t.Helper()
	store, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	if dir != "" {
		args = append([]string{"-C", dir}, args...)
	}
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
