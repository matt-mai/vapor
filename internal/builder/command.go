package builder

import (
	"fmt"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/container"
	"github.com/matt-mai/vapor/internal/vfs"
)

// commandTarget returns the executable the image declares to start with: the
// entrypoint when it has one, otherwise the first word of the command. A relative
// name is looked up on PATH at runtime, which the finished tree cannot answer.
func commandTarget(declared *container.Container) (field, executable string) {
	if len(declared.Entrypoint) > 0 {
		return "entrypoint", declared.Entrypoint[0]
	}
	if len(declared.Cmd) > 0 {
		return "cmd", declared.Cmd[0]
	}
	return "", ""
}

// checkCommand fails when the declared executable is an absolute path the image
// cannot run. Hardening removes shells and package tools by default, so an explicit
// /bin/sh can vanish from a build that otherwise succeeds; reporting it here turns a
// container that cannot start into a build error.
//
// A script names its interpreter in the first line, so an executable script's absolute
// interpreter is checked too. Arguments, including the ones a /usr/bin/env line passes
// on, are a runtime PATH lookup and are left alone.
func checkCommand(tree *vfs.Tree, declared *container.Container) error {
	field, executable := commandTarget(declared)
	if executable == "" || !strings.HasPrefix(executable, "/") {
		return nil
	}
	fault, err := commandFault(tree, executable)
	if err != nil {
		return err
	}
	if fault != "" {
		return fmt.Errorf("container.%s %s %s", field, executable, fault)
	}
	resolved, _, err := commandKind(tree, executable)
	if err != nil {
		return err
	}
	content, err := tree.Read(resolved)
	if err != nil {
		return fmt.Errorf("container.%s %s cannot be read: %w", field, executable, err)
	}
	interpreter := shebang(content)
	if interpreter == "" || !strings.HasPrefix(interpreter, "/") {
		return nil
	}
	if fault, err := commandFault(tree, interpreter); err != nil {
		return err
	} else if fault != "" {
		return fmt.Errorf("container.%s %s starts with %s, which %s",
			field, executable, interpreter, fault)
	}
	return nil
}

// commandFault says why an absolute path cannot be run, or returns the empty string
// when the image holds an executable regular file there. The caller puts the fault in
// a sentence about the field it came from.
func commandFault(tree *vfs.Tree, p string) (string, error) {
	resolved, kind, err := commandKind(tree, p)
	if err != nil {
		return "", err
	}
	if kind == "" {
		return "is not in the image; hardening may have removed it", nil
	}
	if kind != vfs.File {
		return fmt.Sprintf("is a %s, not a file", kind), nil
	}
	entry, ok := tree.Lookup(resolved)
	if !ok {
		return "is not in the image; hardening may have removed it", nil
	}
	if entry.Mode.Perm()&0o111 == 0 {
		return "is not executable", nil
	}
	return "", nil
}

// commandKind resolves an absolute path and reports the kind of the entry it
// names, or the empty kind when the image does not hold it.
func commandKind(tree *vfs.Tree, p string) (string, vfs.Kind, error) {
	resolved, err := tree.Resolve(p)
	if err != nil {
		return "", "", fmt.Errorf("container command %s: %w", p, err)
	}
	entry, ok := tree.Lookup(resolved)
	if !ok {
		return resolved, "", nil
	}
	return resolved, entry.Kind, nil
}

// shebang returns the interpreter a script names on its first line, or the empty
// string when the file does not start with one.
func shebang(content []byte) string {
	line, _, _ := strings.Cut(string(content), "\n")
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
