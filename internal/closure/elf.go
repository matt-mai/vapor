package closure

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// inherited is the RPATH chain an object inherits from the objects that loaded it.
// glibc consults a loader's DT_RPATH for that loader's own dependencies and for
// everything they pull in, so a library is allowed to find its sibling through the
// executable's RPATH. DT_RUNPATH is deliberately not inherited: it applies only to
// the object that carries it.
type inherited []string

func checkObject(tree *vfs.Tree, t target, p string, data io.ReaderAt, from inherited) []error {
	file, err := parse(data)
	if err != nil {
		return []error{fmt.Errorf("%s: %w", p, err)}
	}
	if file.Class != t.class {
		return []error{fmt.Errorf("%s: is ELF class %v, but %s needs %v", p, file.Class, t.triplet, t.class)}
	}
	if file.Machine != t.machine {
		return []error{fmt.Errorf("%s: is machine %v, but %s needs %v", p, file.Machine, t.triplet, t.machine)}
	}
	problems := checkDynamic(tree, t, p, file, from)
	failures := make([]error, 0, len(problems))
	for _, problem := range problems {
		failures = append(failures, fmt.Errorf("%s: %w", p, problem))
	}
	return failures
}

// checkDynamic verifies the interpreter and every DT_NEEDED entry of an object
// that already matched the platform. A problem that ends the check still returns
// the problems found before it.
func checkDynamic(tree *vfs.Tree, t target, p string, file *elf.File, from inherited) []error {
	interpreter, err := interpreterOf(file)
	if err != nil {
		return []error{err}
	}
	var failures []error
	if interpreter != "" {
		resolved, ok := resolveNeeded(tree, interpreter, nil)
		if !ok {
			failures = append(failures, fmt.Errorf("interpreter %s is missing", interpreter))
		} else if loadErr := checkLoadable(tree, t, resolved, true); loadErr != nil {
			failures = append(failures, fmt.Errorf("interpreter %s: %w", interpreter, loadErr))
		}
	}
	if !hasDynamicSection(file) {
		return append(failures, errors.New("has PT_DYNAMIC but no dynamic section, so its libraries cannot be verified"))
	}
	needed, err := importedLibraries(file)
	if err != nil {
		return append(failures, err)
	}
	dirs, err := searchDirs(file, t, path.Dir(p), from)
	if err != nil {
		return append(failures, err)
	}
	for _, name := range needed {
		resolved, ok := resolveNeeded(tree, name, dirs)
		if !ok {
			failures = append(failures, fmt.Errorf("needs %s, which is not in the image", name))
		} else if loadErr := checkLoadable(tree, t, resolved, false); loadErr != nil {
			failures = append(failures, fmt.Errorf("needs %s (%s): %w", name, resolved, loadErr))
		}
	}
	return failures
}

// hasDynamicSection reports whether an object's dynamic segment can be read. A
// segment without the section it describes cannot be verified at all.
func hasDynamicSection(file *elf.File) bool {
	found, err := guard(func() (bool, error) {
		for _, prog := range file.Progs {
			if prog.Type == elf.PT_DYNAMIC {
				return file.SectionByType(elf.SHT_DYNAMIC) != nil, nil
			}
		}
		return true, nil
	})
	return err == nil && found
}

// importedLibraries reads DT_NEEDED through guard, because the section walk behind
// it is as unhardened as the rest of debug/elf.
func importedLibraries(file *elf.File) ([]string, error) {
	return guard(func() ([]string, error) {
		names, err := file.ImportedLibraries()
		if err != nil {
			return nil, fmt.Errorf("read DT_NEEDED: %w", err)
		}
		return names, nil
	})
}

// parse reports a panic from debug/elf as a failure, because that package is not
// hardened against hostile input and package bytes are still untrusted content.
func parse(data io.ReaderAt) (file *elf.File, err error) {
	file, err = guard(func() (*elf.File, error) {
		parsed, parseErr := elf.NewFile(data)
		if parseErr != nil {
			return nil, fmt.Errorf("unparsable ELF content: %w", parseErr)
		}
		return parsed, nil
	})
	return file, err
}

// guard runs one debug/elf operation and reports a panic as a failure.
//
// Every read of an ELF structure goes through it, not just the initial parse:
// debug/elf is not hardened against hostile input, and a package archive is still
// untrusted content, so a future stdlib panic must become a reported failure rather
// than a crash that takes the build down with no diagnosis.
func guard[T any](operation func() (T, error)) (result T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var zero T
			result, err = zero, fmt.Errorf("unparsable ELF content: %v", recovered)
		}
	}()
	return operation()
}

func interpreterOf(file *elf.File) (string, error) {
	return guard(func() (string, error) {
		for _, prog := range file.Progs {
			if prog.Type != elf.PT_INTERP {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(prog.Open(), 4096))
			if err != nil {
				return "", fmt.Errorf("read PT_INTERP: %w", err)
			}
			return strings.TrimRight(string(data), "\x00"), nil
		}
		return "", nil
	})
}

// searchDirs returns the directories a name-only dependency is looked up in,
// which is glibc's order with the runtime-only sources left out.
//
// DT_RUNPATH takes precedence over DT_RPATH when the tag is present, even when it
// holds no usable directory: glibc checks for the tag, not for a non-empty list.
// A RUNPATH of ":" therefore disables RPATH rather than falling back to it, and
// because a RUNPATH also stops the object from inheriting a loader's RPATH, an
// object that carries one searches only its own directories.
//
// Directories are returned unnormalized. Cleaning them here would resolve ".."
// lexically, so "/opt/link/../lib" would become "/opt/lib" even when "/opt/link"
// is a symlink and the loader would reach somewhere else entirely. Resolution
// happens against the tree, where symlinks are known.
func searchDirs(file *elf.File, t target, objectDir string, inherited []string) ([]string, error) {
	runpath, present, err := dynamicPaths(file, elf.DT_RUNPATH)
	if err != nil {
		return nil, err
	}
	dirs := runpath
	if !present {
		rpath, _, err := dynamicPaths(file, elf.DT_RPATH)
		if err != nil {
			return nil, err
		}
		dirs = slices.Concat(inherited, rpath)
	}
	expanded := expandDirs(dirs, objectDir)
	expanded = append(expanded, []string{"/lib/" + t.triplet, "/usr/lib/" + t.triplet, "/lib", "/usr/lib"}...)
	return expanded, nil
}

// expandDirs substitutes $ORIGIN and drops a directory that still holds a token,
// because $LIB and $PLATFORM are not resolved.
func expandDirs(dirs []string, objectDir string) []string {
	expanded := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		dir = strings.ReplaceAll(dir, "${ORIGIN}", objectDir)
		dir = strings.ReplaceAll(dir, "$ORIGIN", objectDir)
		if strings.Contains(dir, "$") {
			continue
		}
		expanded = append(expanded, dir)
	}
	return expanded
}

// dynamicPaths returns the entries of one dynamic tag and whether the tag is
// present at all, which is not the same as holding a usable directory.
func dynamicPaths(file *elf.File, tag elf.DynTag) ([]string, bool, error) {
	type paths struct {
		dirs    []string
		present bool
	}
	read, err := guard(func() (paths, error) {
		values, valueErr := file.DynString(tag)
		if valueErr != nil {
			return paths{}, fmt.Errorf("read %v: %w", tag, valueErr)
		}
		var found paths
		for _, value := range values {
			for dir := range strings.SplitSeq(value, ":") {
				if dir != "" {
					found.dirs = append(found.dirs, dir)
				}
			}
		}
		found.present = len(values) > 0
		return found, nil
	})
	if err != nil {
		return nil, false, err
	}
	return read.dirs, read.present, nil
}

// resolveNeeded returns the tree path a dependency name resolves to.
func resolveNeeded(tree *vfs.Tree, name string, dirs []string) (string, bool) {
	if strings.Contains(name, "/") {
		resolved, err := tree.ResolveUnclean(name)
		if err != nil {
			return "", false
		}
		entry, ok := tree.Lookup(resolved)
		return resolved, ok && entry.Kind == vfs.File
	}
	for _, dir := range dirs {
		// The candidate is resolved as written, not joined: path.Join normalizes
		// ".." lexically, which disagrees with the loader once a component is a
		// symlink. Tree.Resolve expands symlinks as it walks, so ".." then refers to
		// the directory the link actually reaches.
		candidate := strings.TrimSuffix(dir, "/") + "/" + name
		resolved, err := tree.ResolveUnclean(candidate)
		if err != nil {
			continue
		}
		if entry, ok := tree.Lookup(resolved); ok && entry.Kind == vfs.File {
			return resolved, true
		}
	}
	return "", false
}

func checkLoadable(tree *vfs.Tree, t target, p string, interpreter bool) error {
	data, err := tree.OpenFile(p)
	if err != nil {
		return errors.New("cannot read ELF object")
	}
	file, err := parse(data)
	if err != nil {
		return err
	}
	if file.Class != t.class || file.Machine != t.machine || file.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("ELF object does not match %s", t.triplet)
	}
	if file.Type != elf.ET_DYN && (!interpreter || file.Type != elf.ET_EXEC) {
		return fmt.Errorf("ELF type %s is not loadable here", file.Type)
	}
	if segmentErr := checkLoadSegments(file, data.Size()); segmentErr != nil {
		return segmentErr
	}
	if interpreter {
		return nil
	}
	return checkSharedObject(file)
}

func checkLoadSegments(file *elf.File, length int64) error {
	if length < 0 {
		return errors.New("ELF object has an invalid file length")
	}
	size := uint64(length)
	loaded := false
	for _, segment := range file.Progs {
		if segment.Type != elf.PT_LOAD {
			continue
		}
		if segment.Off > size || segment.Filesz > size-segment.Off || segment.Filesz > segment.Memsz {
			return errors.New("ELF object has an invalid load segment")
		}
		loaded = loaded || segment.Filesz > 0
	}
	if !loaded {
		return errors.New("ELF object has no file-backed load segment")
	}
	return nil
}

func checkSharedObject(file *elf.File) error {
	if !slices.ContainsFunc(file.Progs, func(segment *elf.Prog) bool { return segment.Type == elf.PT_DYNAMIC }) {
		return errors.New("ELF library has no dynamic segment")
	}
	flags, err := guard(func() ([]uint64, error) { return file.DynValue(elf.DT_FLAGS_1) })
	if err != nil {
		return fmt.Errorf("read ELF dynamic flags: %w", err)
	}
	for _, flag := range flags {
		if flag&uint64(elf.DF_1_PIE) != 0 {
			return errors.New("ELF executable cannot be loaded as a library")
		}
	}
	return nil
}
