package builder

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/container"
	"github.com/matt-mai/vapor/internal/vfs"
)

func commandTree(t *testing.T, files map[string]string) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	for name, body := range files {
		if err := tree.File(name, []byte(body), vfs.Attrs{Mode: 0o755}); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return tree
}

// Hardening removes shells by default, so an entrypoint naming one has to fail the
// build instead of producing an image that cannot start.
func TestCheckCommand_RejectsAStrippedEntrypoint(t *testing.T) {
	tree := commandTree(t, map[string]string{"/usr/bin/server": "binary"})
	declared := container.Container{Entrypoint: []string{"/bin/sh", "-c", "server"}}
	err := checkCommand(tree, &declared)
	if err == nil || !strings.Contains(err.Error(), "container.entrypoint /bin/sh is not in the image") {
		t.Fatalf("checkCommand = %v", err)
	}
}

func TestCheckCommand_AcceptsAPresentEntrypoint(t *testing.T) {
	tree := commandTree(t, map[string]string{"/usr/bin/server": "binary"})
	declared := container.Container{Entrypoint: []string{"/usr/bin/server"}}
	if err := checkCommand(tree, &declared); err != nil {
		t.Fatalf("checkCommand = %v", err)
	}
}

// A command-less image is valid: the runtime supplies what the image does not
// declare, and a relative name is a PATH lookup.
func TestCheckCommand_IgnoresMissingDeclarations(t *testing.T) {
	tree := vfs.New()
	for _, declared := range []container.Container{
		{},
		{Entrypoint: []string{"sh"}},
		{Cmd: []string{"server", "--port", "8080"}},
	} {
		if err := checkCommand(tree, &declared); err != nil {
			t.Fatalf("checkCommand(%+v) = %v", declared, err)
		}
	}
}

// cmd[0] is the executable when there is no entrypoint.
func TestCheckCommand_ChecksCommandWithoutEntrypoint(t *testing.T) {
	declared := container.Container{Cmd: []string{"/usr/bin/server"}}
	err := checkCommand(vfs.New(), &declared)
	if err == nil || !strings.Contains(err.Error(), "container.cmd /usr/bin/server") {
		t.Fatalf("checkCommand = %v", err)
	}
}

// A symlinked executable is present as long as its target is.
func TestCheckCommand_FollowsSymlinks(t *testing.T) {
	tree := commandTree(t, map[string]string{"/usr/bin/dash": "binary"})
	if err := tree.Symlink("/bin/sh", "/usr/bin/dash", vfs.Attrs{Origin: vfs.Origin{Path: "test"}}); err != nil {
		t.Fatal(err)
	}
	declared := container.Container{Entrypoint: []string{"/bin/sh"}}
	if err := checkCommand(tree, &declared); err != nil {
		t.Fatalf("checkCommand = %v", err)
	}
}

// The interpreter a script names is what actually has to exist.
func TestCheckCommand_ChecksScriptInterpreter(t *testing.T) {
	tree := commandTree(t, map[string]string{"/app/run": "#!/bin/sh\nexec server\n"})
	declared := container.Container{Entrypoint: []string{"/app/run"}}
	err := checkCommand(tree, &declared)
	if err == nil || !strings.Contains(err.Error(), "starts with /bin/sh, which is not in the image") {
		t.Fatalf("checkCommand = %v", err)
	}
	if err := tree.File("/bin/sh", []byte("binary"), vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := checkCommand(tree, &declared); err != nil {
		t.Fatalf("checkCommand with interpreter = %v", err)
	}
}

// The argument of an env line is a runtime PATH lookup, not an image path.
func TestCheckCommand_IgnoresEnvLookup(t *testing.T) {
	tree := commandTree(t, map[string]string{
		"/app/env":     "#!/usr/bin/env python3\nprint('hi')\n",
		"/usr/bin/env": "binary",
	})
	declared := container.Container{Entrypoint: []string{"/app/env"}}
	if err := checkCommand(tree, &declared); err != nil {
		t.Fatalf("checkCommand = %v", err)
	}
}

// An entrypoint that is a directory cannot start, so a path the image holds but
// cannot run is refused rather than accepted because the path exists.
func TestCheckCommand_RejectsADirectory(t *testing.T) {
	tree := commandTree(t, map[string]string{"/usr/bin/server": "binary"})
	if err := tree.Dir("/usr/bin/app", vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	declared := container.Container{Entrypoint: []string{"/usr/bin/app"}}
	err := checkCommand(tree, &declared)
	want := "container.entrypoint /usr/bin/app is a directory, not a file"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkCommand = %v, want %q", err, want)
	}
}

// A file without an execute bit fails to start just like a missing one.
func TestCheckCommand_RejectsANonExecutableFile(t *testing.T) {
	tree := vfs.New()
	if err := tree.File("/usr/bin/server", []byte("binary"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	declared := container.Container{Entrypoint: []string{"/usr/bin/server"}}
	err := checkCommand(tree, &declared)
	want := "container.entrypoint /usr/bin/server is not executable"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkCommand = %v, want %q", err, want)
	}
}

// An interpreter only has to exist today, so a script whose interpreter is a data
// file passes a check that the image cannot actually run.
func TestCheckCommand_RejectsANonExecutableInterpreter(t *testing.T) {
	tree := commandTree(t, map[string]string{"/app/run": "#!/bin/sh\necho hi\n"})
	if err := tree.File("/bin/sh", []byte("not a shell"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	declared := container.Container{Entrypoint: []string{"/app/run"}}
	err := checkCommand(tree, &declared)
	want := "container.entrypoint /app/run starts with /bin/sh, which is not executable"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkCommand = %v, want %q", err, want)
	}
}
