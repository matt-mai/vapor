package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

// vexFixture points the build fixture at an image that makes VEX claims, so the command
// can be exercised end to end: lock the inputs, then render the statements from them.
type vexFixture struct {
	*buildFixture
}

// newVEXFixture appends the VEX section to the fixture specification and writes any
// imported document the section names, so the lock snapshots it like any other input.
func newVEXFixture(t *testing.T, claims string, inputs []vexInput) *vexFixture {
	t.Helper()
	fixture := newBuildFixture(t)
	extra := "vex:\n" + claims
	data, err := os.ReadFile(fixture.specPath)
	if err != nil {
		t.Fatal(err)
	}
	updated := string(data) + extra
	if err := os.WriteFile(fixture.specPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, input := range inputs {
		writeVEXInput(t, fixture, input.name, input.body)
	}
	return &vexFixture{buildFixture: fixture}
}

type vexInput struct {
	name string
	body string
}

func writeVEXInput(t *testing.T, fixture *buildFixture, name, body string) {
	t.Helper()
	path := filepath.Join(fixture.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// vexArgs is the command line the tests use. --output names a fresh directory so the
// written statements are found by name rather than by scanning the fixture.
func (f *vexFixture) vexArgs(output string) []string {
	return []string{"vex", "--spec", f.specPath, "--cache-dir", f.cacheDir, "--output", output}
}

func (f *vexFixture) lockAndVEX(t *testing.T, output string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(f.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code := run(f.vexArgs(output), &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

// vexStatementDocument decodes a written statement and returns its statements.
func vexStatements(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if document["@context"] != "https://openvex.dev/ns/v0.2.0" {
		t.Fatalf("%s is not an OpenVEX v0.2.0 document: %v", path, document["@context"])
	}
	statements, ok := document["statements"].([]any)
	if !ok {
		t.Fatalf("%s has no statements: %v", path, document)
	}
	decoded := make([]map[string]any, 0, len(statements))
	for _, statement := range statements {
		decoded = append(decoded, statement.(map[string]any))
	}
	return decoded
}

// TestRun_VEXWritesAStatementPerPlatform checks the ordinary case: a claim about a locked
// package produces one document per platform, named so it is recognizable on its own.
func TestRun_VEXWritesAStatementPerPlatform(t *testing.T) {
	t.Parallel()
	fixture := newVEXFixture(t, `  assertions:
    - vulnerability: CVE-2026-1000
      package: base-files
      status: fixed
      statement: Upgraded to 26.04
`, nil)
	output := t.TempDir()
	stdout, stderr, code := fixture.lockAndVEX(t, output)
	if code != 0 {
		t.Fatalf("vex code=%d stderr=%q", code, stderr)
	}
	path := filepath.Join(output, "example.invalid-built-linux-amd64.openvex.json")
	if strings.TrimSpace(stdout) != path {
		t.Fatalf("stdout = %q, want the written path", stdout)
	}
	if !strings.Contains(stderr, "write VEX statement") {
		t.Fatalf("vex did not report the statement: %q", stderr)
	}
	statements := vexStatements(t, path)
	if len(statements) != 1 {
		t.Fatalf("statements = %v", statements)
	}
	if statements[0]["status"] != "fixed" {
		t.Fatalf("status = %v", statements[0]["status"])
	}
	products := statements[0]["products"].([]any)
	named := products[0].(map[string]any)["@id"].(string)
	if !strings.HasPrefix(named, "pkg:deb/ubuntu/base-files@26.04") {
		t.Fatalf("product = %q", named)
	}
}

// TestRun_VEXRefusesAClaimTheLockCannotResolve checks that a claim naming content the
// image does not hold fails the command instead of producing a statement that says less
// than the specification did.
func TestRun_VEXRefusesAClaimTheLockCannotResolve(t *testing.T) {
	t.Parallel()
	fixture := newVEXFixture(t, `  assertions:
    - vulnerability: CVE-2026-1001
      package: nosuch
      status: fixed
      statement: Upgraded to 26.04
`, nil)
	stdout, stderr, code := fixture.lockAndVEX(t, t.TempDir())
	if code != 1 || stdout != "" {
		t.Fatalf("vex code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, `package "nosuch" is not locked on linux/amd64`) {
		t.Fatalf("stderr = %q", stderr)
	}
}

// TestRun_VEXRefusesAnImportedAbsenceWithoutEvidence checks the fail-closed rule through
// the command: an imported not_affected claim carries no path of its own, so nothing
// shows why it holds and no statement is written.
func TestRun_VEXRefusesAnImportedAbsenceWithoutEvidence(t *testing.T) {
	t.Parallel()
	document := `{"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.invalid/vex/2026-11-20.json",
	"author": "Example Security Team",
	"timestamp": "2026-11-20T09:00:00Z",
	"version": 1,
	"statements": [{"vulnerability": {"name": "CVE-2026-1002"},
	"products": [{"identifiers": {"purl": "pkg:deb/ubuntu/base-files@26.04"}}],
	"status": "not_affected",
	"justification": "vulnerable_code_not_present"}]}`
	fixture := newVEXFixture(t, "  inputs: [vex/review.json]\n",
		[]vexInput{{name: "vex/review.json", body: document}})
	output := t.TempDir()
	stdout, stderr, code := fixture.lockAndVEX(t, output)
	if code != 1 || stdout != "" {
		t.Fatalf("vex code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "no absent path shows why") {
		t.Fatalf("stderr = %q", stderr)
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused claim still wrote %d files", len(entries))
	}
}

// TestRun_VEXChecksTheFinishedImage checks the evidence end to end: a path the image holds
// refuses the claim, and one it does not hold lets it through with the facts attached.
func TestRun_VEXChecksTheFinishedImage(t *testing.T) {
	t.Parallel()
	claims := `  assertions:
    - vulnerability: CVE-2026-1003
      package: base-files
      status: not_affected
      justification: vulnerable_code_not_present
      statement: The vulnerable file is not shipped
      absent-paths: [%s]
`
	held := newVEXFixture(t, strings.Replace(claims, "%s", "/etc/base-files", 1), nil)
	output := t.TempDir()
	_, stderr, code := held.lockAndVEX(t, output)
	if code != 1 || !strings.Contains(stderr, "/etc/base-files is in the image") {
		t.Fatalf("vex code=%d stderr=%q", code, stderr)
	}
	absent := newVEXFixture(t, strings.Replace(claims, "%s", "/usr/bin/missing", 1), nil)
	if _, stderr, code := absent.lockAndVEX(t, t.TempDir()); code != 0 {
		t.Fatalf("vex code=%d stderr=%q", code, stderr)
	}
}

// TestRun_VEXDisabledCheckIsAVisibleWaiver checks the switch through the command: the
// claim is published, and the payload says that nothing checked it.
func TestRun_VEXDisabledCheckIsAVisibleWaiver(t *testing.T) {
	t.Parallel()
	fixture := newVEXFixture(t, `  check-absent-paths: false
  assertions:
    - vulnerability: CVE-2026-1004
      package: base-files
      status: not_affected
      justification: component_not_present
      statement: The component is not included
`, nil)
	output := t.TempDir()
	stdout, stderr, code := fixture.lockAndVEX(t, output)
	if code != 0 {
		t.Fatalf("vex code=%d stderr=%q", code, stderr)
	}
	statements := vexStatements(t, strings.TrimSpace(stdout))
	notes, _ := statements[0]["status_notes"].(string)
	if !strings.Contains(notes, "were not checked") {
		t.Fatalf("status_notes = %v", statements[0]["status_notes"])
	}
}

// TestRun_VEXImportsALockedDocument checks that an imported document is read from the
// verified cache rather than from the path the specification names: changing the source
// file after locking changes nothing.
func TestRun_VEXImportsALockedDocument(t *testing.T) {
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
	output := t.TempDir()
	stdout, stderr, code := fixture.lockAndVEX(t, output)
	if code != 0 {
		t.Fatalf("vex code=%d stderr=%q", code, stderr)
	}
	statements := vexStatements(t, strings.TrimSpace(stdout))
	if len(statements) != 1 || statements[0]["status"] != "under_investigation" {
		t.Fatalf("statements = %v", statements)
	}
	if err := os.WriteFile(filepath.Join(fixture.dir, "vex", "review.json"),
		[]byte(`{"@context": "https://openvex.dev/ns/v0.2.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runAndReport(t, fixture.vexArgs(t.TempDir())); code != 0 {
		t.Fatalf("vex read the source file instead of the lock: code=%d stderr=%q", code, stderr)
	}
}

// TestRun_VEXRefusesAnEmptyClaimSet checks a specification that makes no claim: writing
// nothing and reporting success would look like a statement nobody needed to write.
func TestRun_VEXRefusesAnEmptyClaimSet(t *testing.T) {
	t.Parallel()
	fixture := newBuildFixture(t)
	stdout, stderr, code := (&vexFixture{buildFixture: fixture}).lockAndVEX(t, t.TempDir())
	if code != 1 || stdout != "" {
		t.Fatalf("vex code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "no VEX claim applies to any declared platform") {
		t.Fatalf("stderr = %q", stderr)
	}
}

// TestRun_VEXSignsWhenAKeyIsNamed checks the opt-in signature through the command: the
// file becomes a DSSE envelope, and the payload inside it is the same document the
// unsigned run writes.
func TestRun_VEXSignsWhenAKeyIsNamed(t *testing.T) {
	t.Parallel()
	fixture := newVEXFixture(t, `  assertions:
    - vulnerability: CVE-2026-1007
      package: base-files
      status: fixed
      statement: Upgraded to 26.04
`, nil)
	unsigned, stderr, code := fixture.lockAndVEX(t, t.TempDir())
	if code != 0 {
		t.Fatalf("vex code=%d stderr=%q", code, stderr)
	}
	key := newTestSigningKey(t, fixture.dir)
	signedDir := t.TempDir()
	stdout, stderr, code := runAndReport(t, append(fixture.vexArgs(signedDir), "--sign-key", key.path))
	if code != 0 {
		t.Fatalf("vex code=%d stderr=%q", code, stderr)
	}
	if strings.TrimSpace(stdout) != filepath.Join(signedDir, filepath.Base(strings.TrimSpace(unsigned))) {
		t.Fatalf("stdout = %q", stdout)
	}
	envelope := readEnvelope(t, strings.TrimSpace(stdout))
	payload, err := envelope.Verify(key.public)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	original, err := os.ReadFile(strings.TrimSpace(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, original) {
		t.Fatalf("the signed payload differs from the unsigned document:\n%s\n%s", payload, original)
	}
	if envelope.PayloadType != attest.PayloadTypeVEX {
		t.Fatalf("payloadType = %q", envelope.PayloadType)
	}
}

// TestRun_VEXRefusesAnUnusableKey checks that a key that cannot be read stops the command
// instead of quietly writing an unsigned statement.
func TestRun_VEXRefusesAnUnusableKey(t *testing.T) {
	t.Parallel()
	fixture := newVEXFixture(t, `  assertions:
    - vulnerability: CVE-2026-1008
      package: base-files
      status: fixed
      statement: Upgraded to 26.04
`, nil)
	var stdout, stderr bytes.Buffer
	if code := run(fixture.args("lock"), &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	broken := filepath.Join(fixture.dir, "broken.pem")
	if err := os.WriteFile(broken, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	outputText, stderrText, code := runAndReport(t,
		append(fixture.vexArgs(output), "--sign-key", broken))
	if code != 1 || outputText != "" {
		t.Fatalf("vex code=%d stdout=%q stderr=%q", code, outputText, stderrText)
	}
	if !strings.Contains(stderrText, "not a PEM document") {
		t.Fatalf("stderr = %q", stderrText)
	}
	if entries, err := os.ReadDir(output); err != nil || len(entries) != 0 {
		t.Fatalf("a refused key still wrote %d files (err=%v)", len(entries), err)
	}
}

// testSigningKey is an Ed25519 key pair written as PKCS#8 PEM in the fixture directory.
type testSigningKey struct {
	path   string
	public ed25519.PublicKey
}

func newTestSigningKey(t *testing.T, dir string) testSigningKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "signing.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return testSigningKey{path: path, public: public}
}

func readEnvelope(t *testing.T, path string) *attest.Envelope {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope attest.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return &envelope
}

func runAndReport(t *testing.T, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}
