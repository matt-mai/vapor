// Package conformance_test checks that the documented v3 conformance matrix names
// tests that exist. It is a test-only package: nothing here is linked into the
// binary, and the checks run only under `go test`.
package conformance_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	matrixPath    = "../../docs/developer/conformance-matrix.md"
	checklistPath = "../../docs/developer/chisel-v3-compatibility.md"
)

// testSources are the packages whose tests the matrix may name.
var testSources = []string{
	"../distro",
	"../distro/slices",
	"../distro/deb",
	"../distro/debian",
	"../distro/ubuntu",
	"../mutation",
	"../vfs",
	"../verify",
	"../acquire",
	"../cache",
	"../locking",
	"../lockinput",
	"../snapshot",
	"../starter",
	"../artifact",
	"../synthesis",
	"../hardening",
	"../closure",
	"../schema",
}

// status is how much evidence a matrix row has.
type status string

const (
	covered     status = "covered"
	blocked     status = "blocked"
	unsupported status = "unsupported"
	resolved    status = "resolved"
)

// row is one line of the conformance matrix.
type row struct {
	id     string
	status status
	tests  []string
	// checklist is the row's description cell, used to match it against the row of
	// the same position in the checklist.
	checklist string
}

var (
	rowPattern  = regexp.MustCompile(`^\|\s*(R\d{2}|P\d{2}|A\d{2}|D\d{2})\s*\|`)
	testPattern = regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")
	funcPattern = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)
)

// parseMatrix reads the matrix rows from the documented markdown table.
func parseMatrix(data []byte) ([]row, error) {
	var rows []row
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(string(data), "\n") {
		match := rowPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		id := match[1]
		if seen[id] {
			return nil, fmt.Errorf("conformance matrix repeats row %s", id)
		}
		seen[id] = true
		state, ok := cellStatus(line)
		if !ok {
			return nil, fmt.Errorf("conformance matrix row %s has no status", id)
		}
		parsed := row{id: id, status: state, checklist: descriptionCell(line)}
		for _, test := range testPattern.FindAllStringSubmatch(line, -1) {
			parsed.tests = append(parsed.tests, test[1])
		}
		rows = append(rows, parsed)
	}
	if len(rows) == 0 {
		return nil, errors.New("conformance matrix has no rows")
	}
	return rows, nil
}

// descriptionCell returns a matrix row's description cell, the one after the ID.
func descriptionCell(line string) string {
	fields := strings.Split(strings.Trim(line, "|"), "|")
	if len(fields) < 2 {
		return ""
	}
	return strings.TrimSpace(fields[1])
}

// cellStatus returns the row's status cell. Cells are compared whole so prose that
// happens to contain the word "covered" cannot be mistaken for a status.
func cellStatus(line string) (status, bool) {
	for cell := range strings.SplitSeq(line, "|") {
		switch status(strings.TrimSpace(cell)) {
		case covered:
			return covered, true
		case blocked:
			return blocked, true
		case unsupported:
			return unsupported, true
		case resolved:
			return resolved, true
		}
	}
	return "", false
}

// verify reports every row whose named tests do not exist and every status that is
// not one of the documented four. known maps test names to the file declaring them,
// so a renamed or deleted test fails here instead of rotting.
func verify(rows []row, known map[string]string) error {
	var problems []error
	for _, r := range rows {
		switch r.status {
		case covered, blocked, unsupported, resolved:
		default:
			problems = append(problems, fmt.Errorf("row %s has unknown status %q", r.id, r.status))
		}
		if r.status == covered && len(r.tests) == 0 {
			problems = append(problems, fmt.Errorf("row %s is covered but names no test", r.id))
		}
		for _, test := range r.tests {
			if _, ok := known[test]; !ok {
				problems = append(problems, fmt.Errorf("row %s names missing test %s", r.id, test))
			}
		}
	}
	return errors.Join(problems...)
}

// knownTests collects the test functions declared in the named Go test files. It
// reads source text rather than running the tests, because the matrix is about
// which tests exist, not what they assert.
func knownTests(files []string) (map[string]string, error) {
	known := make(map[string]string)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("conformance matrix cannot read %s: %w", file, err)
		}
		for _, match := range funcPattern.FindAllSubmatch(data, -1) {
			known[string(match[1])] = file
		}
	}
	return known, nil
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func matrixRows(t *testing.T) []row {
	t.Helper()
	rows, err := parseMatrix(readFile(t, matrixPath))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func repoKnownTests(t *testing.T) map[string]string {
	t.Helper()
	var files []string
	for _, dir := range testSources {
		matches, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Fatal("no test sources found")
	}
	known, err := knownTests(files)
	if err != nil {
		t.Fatal(err)
	}
	return known
}

func TestConformanceMatrix(t *testing.T) {
	if err := verify(matrixRows(t), repoKnownTests(t)); err != nil {
		t.Fatalf("conformance matrix is stale:\n%v", err)
	}
}

// rowsIn returns how many matrix rows carry the given ID prefix.
func rowsIn(rows []row, prefix string) int {
	count := 0
	for _, r := range rows {
		if strings.HasPrefix(r.id, prefix) {
			count++
		}
	}
	return count
}

// tableRows counts the data rows of the markdown table inside section, skipping the
// header and separator.
func tableRows(section string) int {
	count := 0
	for line := range strings.SplitSeq(section, "\n") {
		if strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "| ---") {
			count++
		}
	}
	return count - 1
}

// The checklist is the source of truth for what must be covered. A new row there
// without a matrix row here is the failure these tests exist to catch.
func TestConformanceMatrixCoversEveryChecklistRow(t *testing.T) {
	_, section, ok := strings.Cut(string(readFile(t, checklistPath)),
		"## Fixture seed and feature-to-test checklist")
	if !ok {
		t.Fatal("checklist section missing")
	}
	section, _, ok = strings.Cut(section, "Before claiming full compatibility")
	if !ok {
		t.Fatal("checklist section end missing")
	}
	// Identity, not just count: a checklist row added in the middle would otherwise
	// keep the totals equal while shifting every row below it onto the wrong test.
	checklist := tableFirstCells(section)[1:] // the header row is not a feature
	matrix := matrixRows(t)
	var covered []string
	for _, r := range matrix {
		if strings.HasPrefix(r.id, "R") {
			covered = append(covered, r.checklist)
		}
	}
	if len(checklist) != len(covered) {
		t.Fatalf("checklist has %d feature rows, matrix covers %d", len(checklist), len(covered))
	}
	for i, want := range checklist {
		if got := covered[i]; !sameRow(want, got) {
			t.Fatalf("checklist row %d is %q but matrix row %s describes %q", i+1, want, matrix[i].id, got)
		}
	}
}

// sameRow compares two descriptions by their leading words, so a row may be
// reworded slightly while still being recognizably the same row.
func sameRow(want, got string) bool {
	return leadingWords(want, 5) == leadingWords(got, 5)
}

// leadingWords returns the first n lowercase alphanumeric words of a description.
func leadingWords(text string, n int) string {
	var words []string
	for _, field := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if field == "" {
			continue
		}
		words = append(words, field)
		if len(words) == n {
			break
		}
	}
	return strings.Join(words, " ")
}

// tableFirstCells returns the first cell of every data row in a markdown table.
func tableFirstCells(section string) []string {
	var cells []string
	for line := range strings.SplitSeq(section, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		fields := strings.Split(strings.Trim(line, "|"), "|")
		cells = append(cells, strings.TrimSpace(fields[0]))
	}
	return cells
}

// Debian provider coverage is a separate table from upstream conformance, so the
// check is that it exists rather than that it matches a checklist.
func TestConformanceMatrixRecordsDebianProviderCoverage(t *testing.T) {
	if got := rowsIn(matrixRows(t), "D"); got == 0 {
		t.Fatal("conformance matrix records no Debian provider coverage")
	}
}

// A checklist row inserted in the middle keeps the totals equal while shifting
// every row below it onto the wrong test, so the check compares row identity.
func TestConformanceMatrixMatchesChecklistRowIdentity(t *testing.T) {
	section := "| Feature |\n| --- |\n| alpha beta gamma delta epsilon zeta |\n| one two three four five six |\n"
	checklist := tableFirstCells(section)[1:]
	if len(checklist) != 2 {
		t.Fatalf("checklist = %v", checklist)
	}
	if !sameRow(checklist[0], "alpha beta gamma delta epsilon reworded") {
		t.Fatal("a reworded row should still match")
	}
	if sameRow(checklist[0], checklist[1]) {
		t.Fatal("different rows matched")
	}
}

func TestConformanceMatrixRecordsEveryPolicy(t *testing.T) {
	_, section, ok := strings.Cut(string(readFile(t, checklistPath)),
		"## Intentional Vapor policies versus upstream behavior")
	if !ok {
		t.Fatal("policy section missing")
	}
	section, _, ok = strings.Cut(section, "### Static observations needing executable decisions")
	if !ok {
		t.Fatal("policy section end missing")
	}
	if want, got := tableRows(section), rowsIn(matrixRows(t), "P"); want != got {
		t.Fatalf("checklist records %d policies, matrix covers %d", want, got)
	}
}

func TestConformanceMatrixRecordsEveryAmbiguity(t *testing.T) {
	_, section, ok := strings.Cut(string(readFile(t, checklistPath)),
		"### Static observations needing executable decisions")
	if !ok {
		t.Fatal("ambiguity section missing")
	}
	section, _, ok = strings.Cut(section, "## Fixture seed and feature-to-test checklist")
	if !ok {
		t.Fatal("ambiguity section end missing")
	}
	bullets := 0
	for line := range strings.SplitSeq(section, "\n") {
		if strings.HasPrefix(line, "- ") {
			bullets++
		}
	}
	if got := rowsIn(matrixRows(t), "A"); got < bullets {
		t.Fatalf("checklist records %d ambiguities, matrix covers %d", bullets, got)
	}
}

func TestParseMatrixRejectsBadRows(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"no rows", "| nothing | here |\n", "no rows"},
		{"duplicate id", "| R01 | x | covered | `TestA` |\n| R01 | y | covered | `TestA` |\n", "repeats row R01"},
		{"missing status", "| R01 | x | `TestA` |\n", "no status"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseMatrix([]byte(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyRejectsStaleRows(t *testing.T) {
	known := map[string]string{"TestExists": "a_test.go"}
	tests := []struct {
		name string
		row  row
		want string
	}{
		{"missing test", row{id: "R01", status: covered, tests: []string{"TestGone"}}, "missing test TestGone"},
		{"unknown status", row{id: "R01", status: "maybe"}, "unknown status"},
		{"covered without tests", row{id: "R01", status: covered}, "names no test"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verify([]row{tc.row}, known)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	if err := verify([]row{
		{id: "R01", status: covered, tests: []string{"TestExists"}},
		{id: "R02", status: blocked},
		{id: "R03", status: unsupported, tests: []string{"TestExists"}},
		{id: "A01", status: resolved, tests: []string{"TestExists"}},
	}, known); err != nil {
		t.Fatalf("valid rows failed: %v", err)
	}
}

func TestKnownTestsReadsDeclarations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x_test.go")
	source := "package x\n\nfunc TestOne(t *testing.T) {}\n\nfunc TestTwo(t *testing.T) {}\n\nfunc helper() {}\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	known, err := knownTests([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 2 || known["TestOne"] != path || known["TestTwo"] != path {
		t.Fatalf("known = %v", known)
	}
	if _, err := knownTests([]string{filepath.Join(dir, "missing_test.go")}); err == nil {
		t.Fatal("missing file accepted")
	}
}

// Guard against a matrix that silently drops a section: the file must still explain
// what each status means and record both blockers.
func TestMatrixDocumentsStatusesAndBlockers(t *testing.T) {
	data := string(readFile(t, matrixPath))
	for _, want := range []string{"`covered`", "`blocked`", "`unsupported`", "9.3.1", "6.10.1"} {
		if !strings.Contains(data, want) {
			t.Fatalf("matrix does not mention %q", want)
		}
	}
	for _, heading := range []string{`^## Blockers$`, `^## Other external authorities$`} {
		if !regexp.MustCompile("(?m)" + heading).MatchString(data) {
			t.Fatalf("matrix has no %s section", heading)
		}
	}
}
