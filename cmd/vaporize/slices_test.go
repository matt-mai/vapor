package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const catalogueFixture = "../../internal/distro/slices/testdata/chisel-v3/catalogue"

func TestRun_SlicesListAndShow(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"slices", "list", "--catalogue", catalogueFixture}, &stdout, &stderr); code != 0 {
		t.Fatalf("list code=%d stderr=%q", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) < 2 || lines[0] != "base-files/copyright" || lines[len(lines)-1] != "provider/data" {
		t.Fatalf("list output=%q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"slices", "list", "--catalogue", catalogueFixture, "--package", "base-files"}, &stdout, &stderr); code != 0 {
		t.Fatalf("filtered list code=%d stderr=%q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "base-files/copyright\nbase-files/etc\nbase-files/lib\nbase-files/release-info" {
		t.Fatalf("filtered list=%q", got)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"slices", "show", "base-files/etc", "--catalogue", catalogueFixture}, &stdout, &stderr); code != 0 {
		t.Fatalf("show code=%d stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"package: base-files", "slice: etc", "essential:", "/etc/"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("show output=%q missing %q", stdout.String(), want)
		}
	}
}

func TestRun_SlicesCheck(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"slices", "check", "--catalogue", catalogueFixture}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "catalogue OK") {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	dir := t.TempDir()
	metadata, err := os.ReadFile(filepath.Join(catalogueFixture, "chisel.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "slices"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chisel.yaml"), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "slices", "bad.yaml"), []byte("package: bad\narchive: missing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "slices", "worse.yaml"), []byte("package: worse\nunknown: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"slices", "check", "--catalogue", dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("bad check code=%d stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"bad.yaml", "worse.yaml"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr=%q missing %q", stderr.String(), want)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"slices", "list"}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing catalogue code=%d stderr=%q", code, stderr.String())
	}
}

func TestRun_SlicesCheckStoreBacked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	metadata, err := os.ReadFile(filepath.Join(catalogueFixture, "chisel.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chisel.yaml"), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "slices"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "bin-slices"), 0o755); err != nil {
		t.Fatal(err)
	}
	definition := "package: demo\nstore: bin\ndefault-track: 1\nslices:\n  runtime: {}\n"
	if err := os.WriteFile(filepath.Join(dir, "bin-slices", "demo.yaml"), []byte(definition), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"slices", "check", "--catalogue", dir}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "catalogue OK") {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
