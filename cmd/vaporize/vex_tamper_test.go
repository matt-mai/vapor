package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

// lockedInputBlob returns the cache path of the one local input the lock recorded under
// the given role, so a test can corrupt exactly that payload and nothing else.
func lockedInputBlob(t *testing.T, fixture *buildFixture, role string) string {
	t.Helper()
	locked, err := lock.LoadLockfile(fixture.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	for _, record := range locked.LocalInputs {
		if record.Role != role {
			continue
		}
		if digest != "" {
			t.Fatalf("lock records two %q inputs", role)
		}
		digest = record.SHA256
	}
	if digest == "" {
		t.Fatalf("lock records no %q input", role)
	}
	return filepath.Join(fixture.cacheDir, "sha256", digest[:2], digest)
}

// TestRun_VEXRefusesATamperedLockedDocument checks that a VEX input whose cached bytes
// were replaced after locking is refused rather than read: the lock's digest is what
// makes the claim trustworthy, so a mismatch has to stop the command.
func TestRun_VEXRefusesATamperedLockedDocument(t *testing.T) {
	t.Parallel()
	document := `{"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.invalid/vex/2026-11-20.json",
	"author": "Example Security Team",
	"timestamp": "2026-11-20T09:00:00Z",
	"version": 1,
	"statements": [{"vulnerability": {"name": "CVE-2026-1005"},
	"products": [{"identifiers": {"purl": "pkg:deb/ubuntu/base-files@26.04"}}],
	"status": "not_affected", "justification": "vulnerable_code_not_present"}]}`
	fixture := newVEXFixture(t, "  inputs: [vex/review.json]\n",
		[]vexInput{{name: "vex/review.json", body: document}})
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	blob := lockedInputBlob(t, fixture.buildFixture, kindVEX)
	tampered := strings.Replace(document, "not_affected", "affected", 1)
	if err := os.WriteFile(blob, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.vexArgs(output), &stdout, &stderr); code != 1 {
		t.Fatalf("tampered document accepted: code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "read VEX input") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if entries, err := os.ReadDir(output); err != nil || len(entries) != 0 {
		t.Fatalf("a refused run wrote %d files: %v", len(entries), err)
	}
}

// TestRun_VEXRefusesADeletedLockedDocument checks the same boundary from the other
// side: a payload that is gone cannot be silently skipped, because the claim it holds
// would then disappear without a report.
func TestRun_VEXRefusesADeletedLockedDocument(t *testing.T) {
	t.Parallel()
	document := `{"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.invalid/vex/2026-11-20.json",
	"author": "Example Security Team",
	"timestamp": "2026-11-20T09:00:00Z",
	"version": 1,
	"statements": [{"vulnerability": {"name": "CVE-2026-1005"},
	"products": [{"identifiers": {"purl": "pkg:deb/ubuntu/base-files@26.04"}}],
	"status": "under_investigation"}]}`
	fixture := newVEXFixture(t, "  inputs: [vex/review.json]\n",
		[]vexInput{{name: "vex/review.json", body: document}})
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	if err := os.Remove(lockedInputBlob(t, fixture.buildFixture, kindVEX)); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.vexArgs(t.TempDir()), &stdout, &stderr); code != 1 {
		t.Fatalf("deleted document accepted: code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "read VEX input") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// TestRun_VEXRefusesAnOversizedLockedDocument checks that a locked record bigger than the
// document limit is refused before its blob is opened, so the read never allocates for
// content the decoder would reject anyway.
func TestRun_VEXRefusesAnOversizedLockedDocument(t *testing.T) {
	t.Parallel()
	document := `{"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.invalid/vex/2026-11-20.json",
	"author": "Example Security Team",
	"timestamp": "2026-11-20T09:00:00Z",
	"version": 1,
	"statements": [{"vulnerability": {"name": "CVE-2026-1006"},
	"products": [{"identifiers": {"purl": "pkg:deb/ubuntu/base-files@26.04"}}],
	"status": "not_affected", "justification": "vulnerable_code_not_present"}]}`
	fixture := newVEXFixture(t, "  inputs: [vex/review.json]\n",
		[]vexInput{{name: "vex/review.json", body: document}})
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	locked, err := lock.LoadLockfile(fixture.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	for position := range locked.LocalInputs {
		record := &locked.LocalInputs[position]
		if record.Role == kindVEX {
			record.Size = attest.MaxVEXDocumentSize + 1
		}
	}
	if err := lock.PublishLockfile(fixture.lockPath, locked); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lockedInputBlob(t, fixture.buildFixture, kindVEX)); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(fixture.vexArgs(t.TempDir()), &stdout, &stderr); code != 1 {
		t.Fatalf("oversized record accepted: code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "more than the") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "read VEX input") {
		t.Fatalf("the oversized record was opened anyway: %q", stderr.String())
	}
}
