package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestRun_OutdatedReportsANewerPackage changes what the repository offers after a lock
// was written, then asks whether there is anything to rebuild for. The command has to
// see the new version while downloading no package: the archive's counter proves the
// answer came from metadata alone.
func TestRun_OutdatedReportsANewerPackage(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	fixture.install(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.outdatedArgs(), &stdout, &stderr); code != 0 {
		t.Fatalf("outdated code=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "no updates" {
		t.Fatalf("outdated printed %q, want no updates", got)
	}
	// Re-serve the archive with a newer version of the package the image contains.
	fixture.upgrade(t, "hello", "26.05")
	stdout.Reset()
	stderr.Reset()
	code := run(fixture.outdatedArgs(), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("outdated code=%d, want 1; stderr=%q", code, stderr.String())
	}
	want := "linux/amd64 package hello 26.04 -> 26.05\nlinux/arm64 package hello 26.04 -> 26.05"
	if got := strings.TrimSpace(stdout.String()); got != want {
		t.Fatalf("outdated stdout =\n%s\nwant\n%s", got, want)
	}
}

// TestRun_OutdatedFetchesNoPayload proves the update check costs metadata only. Every
// payload URL is refused after the lock is written, and the answer still arrives, so
// the command cannot have depended on one.
func TestRun_OutdatedFetchesNoPayload(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	fixture.install(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	fixture.refuse(t, func(path string) bool {
		return strings.HasPrefix(path, "/pool/") || strings.HasPrefix(path, "/artifacts/")
	})
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.outdatedArgs(), &stdout, &stderr); code != 0 {
		t.Fatalf("outdated code=%d stderr=%q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "no updates" {
		t.Fatalf("outdated printed %q, want no updates", got)
	}
}

// TestRun_OutdatedRejectsAnotherSpec stops when the lock was made from a different
// specification: the answer would describe an image nobody asked about.
func TestRun_OutdatedRejectsAnotherSpec(t *testing.T) {
	t.Parallel()
	fixture := newOfflineFixture(t)
	fixture.install(t)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	edited := strings.Replace(fixture.specYAML(t), "  packages:\n    - name: hello\n", "  packages: []\n", 1)
	if err := os.WriteFile(fixture.specPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := run(fixture.outdatedArgs(), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("outdated code=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "run vaporize lock first") {
		t.Fatalf("stderr = %q, want a re-lock hint", stderr.String())
	}
}

func (f *offlineFixture) outdatedArgs() []string {
	return []string{
		"outdated", "--lock", f.lockPath, "--spec", f.specPath, "--cache-dir", f.cacheDir,
	}
}
