package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/spec"
)

func initArgs(dir string) []string {
	return []string{"init", "--distro", "ubuntu", "--release", "26.04", "--name", "app", "--dir", dir}
}

func TestRun_InitSuccessAndOverwrite(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "image")
	var stdout, stderr bytes.Buffer
	args := initArgs(dir)
	if code := run(args, &stdout, &stderr); code != 0 || stdout.String() != "Created image.yaml\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := spec.LoadSpec(filepath.Join(dir, "image.yaml")); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "without overwrite") {
		t.Fatalf("overwrite code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRun_InitHelp(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"init", "--help"}, {"help", "init"}, {"init", "-h"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("%v: code=%d stderr=%q", args, code, stderr.String())
		}
		for _, part := range []string{"Usage:", "--distro", "--release", "--name", "--dir"} {
			if !strings.Contains(stdout.String(), part) {
				t.Fatalf("%v: missing %q in help", args, part)
			}
		}
		if strings.Contains(stdout.String(), "not implemented yet") {
			t.Fatal("init help still advertises a stub")
		}
	}
}

func TestRun_InitRequiredFlagsAndInvocation(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--distro", "--release", "--name", "--dir"} {
		t.Run(flag, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "must-not-exist")
			args := initArgs(dir)
			index := slices.Index(args, flag)
			args = slices.Delete(args, index, index+2)
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "required flag "+flag) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("missing flags touched output: %v", err)
			}
		})
	}
	for _, extra := range []string{"--unknown", "extra-argument"} {
		dir := filepath.Join(t.TempDir(), "must-not-exist")
		var stdout, stderr bytes.Buffer
		if code := run(append(initArgs(dir), extra), &stdout, &stderr); code != 2 || stderr.Len() == 0 {
			t.Fatalf("%q code=%d stderr=%q", extra, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"init"}, &stdout, &stderr); code != 2 {
		t.Fatalf("bare init code=%d", code)
	}
}

func TestRun_InitOperationalFailures(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ flag, value string }{
		{"--name", ""}, {"--name", "../outside"}, {"--name", "a..b"},
		{"--distro", "debian"}, {"--release", "99.99"}, {"--dir", ""},
	} {
		dir := filepath.Join(t.TempDir(), "must-not-exist")
		args := initArgs(dir)
		args[slices.Index(args, test.flag)+1] = test.value
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%q: code=%d stdout=%q stderr=%q", test.flag, code, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("validation touched output: %v", err)
		}
	}
	dir := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(dir, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(initArgs(filepath.Join(dir, "image")), &stdout, &stderr); code != 1 || stderr.Len() == 0 {
		t.Fatalf("filesystem failure code=%d stderr=%q", code, stderr.String())
	}
}

func TestRun_InitOutputFailureRetainsSpec(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "image")
	var stderr bytes.Buffer
	if code := run(initArgs(dir), failingWriter{}, &stderr); code != 1 {
		t.Fatalf("output failure code=%d", code)
	}
	if _, err := spec.LoadSpec(filepath.Join(dir, "image.yaml")); err != nil {
		t.Fatalf("completed output lost after status-write failure: %v", err)
	}
}
