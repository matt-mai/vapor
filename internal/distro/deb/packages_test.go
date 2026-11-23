package deb_test

import (
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

const (
	validSHA256      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validSHA256Upper = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
)

const validPackage = `Package: demo
Version: 1.0-1
Architecture: amd64
Filename: pool/main/d/demo/demo_1.0-1_amd64.deb
Size: 1234
SHA256: ` + validSHA256 + `
Pre-Depends: base-files
Depends: libc6 (>= 2.34), libfoo | libbar
Provides: demo (= 1.0)
Conflicts: old-demo
Breaks: old-demo (<< 1.0)
Replaces: old-demo
`

const allPackage = `Package: helper
Version: 2.0
Architecture: all
Filename: pool/main/h/helper/helper_2.0_all.deb
Size: 42
SHA256: ` + validSHA256Upper + `
`

func TestParsePackages(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	packages, err := deb.ParsePackages([]byte(validPackage+"\n"+allPackage), &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("len(packages) = %d", len(packages))
	}
	pkg := packages[0]
	if pkg.Name != "demo" || pkg.Version != "1.0-1" || pkg.Architecture != "amd64" {
		t.Fatalf("package = %+v", pkg)
	}
	if pkg.Origin != (deb.PackageOrigin{Suite: "resolute", Component: "main"}) {
		t.Fatalf("origin = %+v", pkg.Origin)
	}
	if pkg.Filename != "pool/main/d/demo/demo_1.0-1_amd64.deb" || pkg.Size != 1234 || pkg.SHA256 != validSHA256 {
		t.Fatalf("archive evidence = %+v", pkg)
	}
	if got := strings.Join(pkg.Relations.PreDepends, "|"); got != "base-files" {
		t.Fatalf("pre-depends = %q", got)
	}
	if got := strings.Join(pkg.Relations.Depends, "|"); got != "libc6 (>= 2.34)|libfoo | libbar" {
		t.Fatalf("depends = %q", got)
	}
	if got := strings.Join(pkg.Relations.Provides, "|"); got != "demo (= 1.0)" {
		t.Fatalf("provides = %q", got)
	}
	if got := strings.Join(pkg.Relations.Conflicts, "|"); got != "old-demo" {
		t.Fatalf("conflicts = %q", got)
	}
	if got := strings.Join(pkg.Relations.Breaks, "|"); got != "old-demo (<< 1.0)" {
		t.Fatalf("breaks = %q", got)
	}
	if got := strings.Join(pkg.Relations.Replaces, "|"); got != "old-demo" {
		t.Fatalf("replaces = %q", got)
	}
	if packages[1].Architecture != "all" || packages[1].SHA256 != validSHA256 {
		t.Fatalf("all package = %+v", packages[1])
	}
}

// TestParsePackagesSource checks the source package a binary was built from: the field
// names it, sometimes with a source version in parentheses, and an absent field leaves
// it empty rather than guessing the package's own name.
func TestParsePackagesSource(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	cases := map[string]struct{ field, want string }{
		"named":   {"Source: openssl\n", "openssl"},
		"version": {"Source: openssl (3.0.13-0ubuntu3.5)\n", "openssl"},
		"absent":  {"", ""},
	}
	for name, testCase := range cases {
		packages, err := deb.ParsePackages([]byte(validPackage+testCase.field), &index, "resolute")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if packages[0].Source != testCase.want {
			t.Fatalf("%s: source = %q, want %q", name, packages[0].Source, testCase.want)
		}
	}
	if _, err := deb.ParsePackages([]byte(validPackage+"Source: Openssl\n"), &index, "resolute"); err == nil {
		t.Fatal("a source name outside the package grammar was accepted")
	}
}

func TestParsePackagesPreservesOrder(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	data := strings.ReplaceAll(validPackage, "Package: demo", "Package: zeta") + "\n" +
		strings.ReplaceAll(validPackage, "Package: demo", "Package: alpha")
	packages, err := deb.ParsePackages([]byte(data), &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 || packages[0].Name != "zeta" || packages[1].Name != "alpha" {
		t.Fatalf("packages = %+v", packages)
	}
}

func TestParsePackagesRelations(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	data := strings.Replace(validPackage,
		"Depends: libc6 (>= 2.34), libfoo | libbar",
		"Depends: libc6 (>= 2.34),\n libfoo | libbar,\n libbaz\nDescription: first\n continuation\n .", 1)
	packages, err := deb.ParsePackages([]byte(data), &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(packages[0].Relations.Depends, "|"); got != "libc6 (>= 2.34)|libfoo | libbar|libbaz" {
		t.Fatalf("depends = %q", got)
	}
}

func TestParsePackagesEmptyRelationField(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	data := strings.Replace(validPackage, "Depends: libc6 (>= 2.34), libfoo | libbar", "Depends:", 1)
	packages, err := deb.ParsePackages([]byte(data), &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if packages[0].Relations.Depends != nil {
		t.Fatalf("depends = %v", packages[0].Relations.Depends)
	}
}

func TestParsePackagesCaseInsensitiveFields(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	want, err := deb.ParsePackages([]byte(validPackage), &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		transform func(string) string
	}{
		{"uppercase", strings.ToUpper},
		{"lowercase", strings.ToLower},
		{"mixed", mixedCaseField},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := deb.ParsePackages([]byte(transformFieldNames(validPackage, test.transform)), &index, "resolute")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("packages = %+v, want %+v", got, want)
			}
		})
	}
}

func mixedCaseField(name string) string {
	result := []byte(strings.ToLower(name))
	for i := 0; i < len(result); i += 2 {
		if result[i] >= 'a' && result[i] <= 'z' {
			result[i] -= 'a' - 'A'
		}
	}
	return string(result)
}

func transformFieldNames(data string, transform func(string) string) string {
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	for i, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			lines[i] = transform(name) + ":" + value
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestParsePackagesRejectsCaseInsensitiveDuplicates(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	tests := map[string]string{
		"dependency": validPackage + "dEPENDS: libc6\n",
		"required":   validPackage + "pACKAGE: other\n",
		"discarded":  validPackage + "Description: first\nDESCRIPTION: second\n",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := deb.ParsePackages([]byte(data), &index, "resolute"); err == nil {
				t.Fatal("accepted a case-insensitive duplicate field")
			}
		})
	}
}

func TestParsePackagesDiscardsLargeDescription(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	var data strings.Builder
	data.WriteString(validPackage)
	data.WriteString("Description: demo\n")
	for range 100000 {
		data.WriteString(" description continuation\n")
	}
	packages, err := deb.ParsePackages([]byte(data.String()), &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0].Name != "demo" {
		t.Fatalf("packages = %+v", packages)
	}
}

func TestParsePackagesDescriptionAllocationIsBounded(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	var data strings.Builder
	data.WriteString(validPackage)
	data.WriteString("Description: demo\n")
	for range 200000 {
		data.WriteString(" x\n")
	}
	payload := []byte(data.String())

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := deb.ParsePackages(payload, &index, "resolute"); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(len(payload)) * 32; allocated > limit {
		t.Fatalf("allocated %d bytes for a %d-byte index, limit %d", allocated, len(payload), limit)
	}
}

func TestParsePackagesDuplicateDiscardedField(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	data := validPackage + "Description: first\nDescription: second\n"
	if _, err := deb.ParsePackages([]byte(data), &index, "resolute"); err == nil {
		t.Fatal("accepted a duplicate discarded field")
	}
}

func TestParsePackagesUnknownFieldOnlyStanza(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	if _, err := deb.ParsePackages([]byte("Description: ignored\n\n"), &index, "resolute"); err == nil {
		t.Fatal("accepted a stanza without required fields")
	}
}

func TestParsePackagesFieldAndStanzaBounds(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	line := strings.Repeat("a", 1024)
	var fieldData strings.Builder
	fieldData.WriteString(allPackage)
	fieldData.WriteString("Description: ignored\n")
	fieldData.WriteString("Depends: first\n")
	for range deb.MaxPackageFieldSize/1024 + 1 {
		fieldData.WriteString(" ")
		fieldData.WriteString(line)
		fieldData.WriteString("\n")
	}
	if _, err := deb.ParsePackages([]byte(fieldData.String()), &index, "resolute"); err == nil || !strings.Contains(err.Error(), "field exceeds") {
		t.Fatalf("field bound error = %v", err)
	}

	large := strings.Repeat("a", 600*1024)
	stanzaData := allPackage + "Depends: " + large + "\nProvides: " + large + "\n"
	if _, err := deb.ParsePackages([]byte(stanzaData), &index, "resolute"); err == nil || !strings.Contains(err.Error(), "stanza exceeds") {
		t.Fatalf("stanza bound error = %v", err)
	}

	var fieldCount strings.Builder
	fieldCount.WriteString(allPackage)
	for i := range deb.MaxPackageFields + 1 {
		fmt.Fprintf(&fieldCount, "X-%d: ignored\n", i)
	}
	if _, err := deb.ParsePackages([]byte(fieldCount.String()), &index, "resolute"); err == nil || !strings.Contains(err.Error(), "fields") {
		t.Fatalf("field count error = %v", err)
	}
}

func TestParsePackagesEmptyIndex(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	packages, err := deb.ParsePackages(nil, &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 0 {
		t.Fatalf("packages = %+v", packages)
	}
}

func TestParsePackagesRejectsMalformed(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	tests := []struct {
		name  string
		data  string
		index deb.Index
		suite string
	}{
		{"missing package", strings.Replace(validPackage, "Package: demo\n", "", 1), index, "resolute"},
		{"missing version", strings.Replace(validPackage, "Version: 1.0-1\n", "", 1), index, "resolute"},
		{"missing architecture", strings.Replace(validPackage, "Architecture: amd64\n", "", 1), index, "resolute"},
		{"missing filename", strings.Replace(validPackage, "Filename: pool/main/d/demo/demo_1.0-1_amd64.deb\n", "", 1), index, "resolute"},
		{"missing size", strings.Replace(validPackage, "Size: 1234\n", "", 1), index, "resolute"},
		{"missing sha256", strings.Replace(validPackage, "SHA256: "+validSHA256+"\n", "", 1), index, "resolute"},
		{"invalid package name", strings.Replace(validPackage, "Package: demo", "Package: Demo", 1), index, "resolute"},
		{"invalid version", strings.Replace(validPackage, "Version: 1.0-1", "Version: latest", 1), index, "resolute"},
		{"empty epoch", strings.Replace(validPackage, "Version: 1.0-1", "Version: 1:", 1), index, "resolute"},
		{"empty revision", strings.Replace(validPackage, "Version: 1.0-1", "Version: 1-", 1), index, "resolute"},
		{"forbidden version character", strings.Replace(validPackage, "Version: 1.0-1", "Version: 1_0", 1), index, "resolute"},
		{"empty epoch before colon", strings.Replace(validPackage, "Version: 1.0-1", "Version: :1", 1), index, "resolute"},
		{"colon without epoch", strings.Replace(validPackage, "Version: 1.0-1", "Version: 1.0:1", 1), index, "resolute"},
		{"invalid revision character", strings.Replace(validPackage, "Version: 1.0-1", "Version: 1.0-1_2", 1), index, "resolute"},
		{"foreign architecture", strings.Replace(validPackage, "Architecture: amd64", "Architecture: arm64", 1), index, "resolute"},
		{"traversing filename", strings.Replace(validPackage, "pool/main/d/demo/demo_1.0-1_amd64.deb", "../demo.deb", 1), index, "resolute"},
		{"non-deb filename", strings.Replace(validPackage, "demo_1.0-1_amd64.deb", "demo_1.0-1_amd64.tar", 1), index, "resolute"},
		{"query filename", strings.Replace(validPackage, "demo_1.0-1_amd64.deb", "demo_1.0-1_amd64.deb?x=1", 1), index, "resolute"},
		{"short sha256", strings.Replace(validPackage, validSHA256, "abc", 1), index, "resolute"},
		{"non-hex sha256", strings.Replace(validPackage, validSHA256, strings.Repeat("z", 64), 1), index, "resolute"},
		{"negative size", strings.Replace(validPackage, "Size: 1234", "Size: -1", 1), index, "resolute"},
		{"non-numeric size", strings.Replace(validPackage, "Size: 1234", "Size: huge", 1), index, "resolute"},
		{"signed size", strings.Replace(validPackage, "Size: 1234", "Size: +1", 1), index, "resolute"},
		{"overflowing size", strings.Replace(validPackage, "Size: 1234", "Size: 99999999999999999999", 1), index, "resolute"},
		{"duplicate field", validPackage + "Version: 2.0\n", index, "resolute"},
		{"continuation before field", "\torphan\n" + validPackage, index, "resolute"},
		{"malformed line", "not a field\n" + validPackage, index, "resolute"},
		{"invalid field name", strings.Replace(validPackage, "Package:", "-Package:", 1), index, "resolute"},
		{"empty relation", validPackage + "Depends: a,,b\n", index, "resolute"},
		{"invalid utf8", validPackage + "\xff", index, "resolute"},
		{"nul byte", strings.Replace(validPackage, "demo", "de\x00mo", 1), index, "resolute"},
		{"missing suite", validPackage, index, ""},
		{"missing component", validPackage, deb.Index{Architecture: "amd64"}, "resolute"},
		{"missing index architecture", validPackage, deb.Index{Component: "main"}, "resolute"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := deb.ParsePackages([]byte(test.data), &test.index, test.suite); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParsePackagesVersions(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	for _, version := range []string{
		"0",
		"1.0",
		"1.0-1",
		"1:1.0-1",
		"1.0~rc1",
		"1.0+git20240101",
		"1.0-1+b1",
		"1.0-1~bpo1",
		"1.0-1.1",
		"1:1.0-1-2",
	} {
		t.Run(version, func(t *testing.T) {
			data := strings.Replace(validPackage, "Version: 1.0-1", "Version: "+version, 1)
			packages, err := deb.ParsePackages([]byte(data), &index, "resolute")
			if err != nil {
				t.Fatal(err)
			}
			if len(packages) != 1 || packages[0].Version != version {
				t.Fatalf("packages = %+v", packages)
			}
		})
	}
}

func TestParsePackagesLineBound(t *testing.T) {
	index := deb.Index{Component: "main", Architecture: "amd64"}
	data := "Package: " + strings.Repeat("a", deb.MaxPackageLineSize) + "\n"
	if _, err := deb.ParsePackages([]byte(data), &index, "resolute"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestSignedIndexToCandidates(t *testing.T) {
	entity, _ := entities(t)
	content := []byte(validPackage)
	compressed := gzipData(t, content)
	hash := releaseFile(compressed)
	path := "main/binary-amd64/Packages.gz"
	payload := releasePayload + "Acquire-By-Hash: yes\nSHA256:\n " +
		hash.SHA256 + " " + strconv.FormatInt(hash.Size, 10) + " " + path + "\n"
	verified, err := deb.VerifyInRelease(signInRelease(t, entity, payload), trustedKeys(t, entity), deb.VerifyOptions{Policy: deb.EnforceExpiry})
	if err != nil {
		t.Fatal(err)
	}
	index, err := deb.SelectIndex(&verified.Metadata, "main", "amd64", deb.ByHashPrefer)
	if err != nil {
		t.Fatal(err)
	}
	if index.Format != deb.IndexFormatGzip {
		t.Fatalf("format = %q", index.Format)
	}
	if want := "main/binary-amd64/by-hash/SHA256/" + hash.SHA256; index.AcquirePaths[0] != want {
		t.Fatalf("acquire paths = %v", index.AcquirePaths)
	}
	decompressed, err := deb.VerifyIndex(&index, compressed)
	if err != nil {
		t.Fatal(err)
	}
	packages, err := deb.ParsePackages(decompressed, &index, "resolute")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0].Name != "demo" || packages[0].SHA256 != validSHA256 {
		t.Fatalf("packages = %+v", packages)
	}
}
