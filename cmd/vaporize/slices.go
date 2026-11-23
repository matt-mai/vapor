package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/catalogue"
	slicespkg "github.com/matt-mai/vapor/internal/distro/slices"
)

type slicesOptions struct {
	catalogue string
	packages  []string
}

func newSlicesCommand() *cobra.Command {
	options := &slicesOptions{}
	command := &cobra.Command{
		Use:   "slices",
		Short: "Explore Chisel slices",
	}
	command.PersistentFlags().StringVar(&options.catalogue, "catalogue", "", "catalogue directory containing chisel.yaml")
	command.AddCommand(newSlicesListCommand(options))
	command.AddCommand(newSlicesShowCommand(options))
	command.AddCommand(newSlicesCheckCommand(options))
	return command
}

func newSlicesListCommand(options *slicesOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List slices in a catalogue",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return options.list(cmd.OutOrStdout())
		},
	}
	command.Flags().StringArrayVar(&options.packages, "package", nil, "only list slices from this package (repeatable)")
	return command
}

func (options *slicesOptions) list(out io.Writer) error {
	packages, err := options.load()
	if err != nil {
		return err
	}
	selected := make(map[string]bool, len(options.packages))
	for _, name := range options.packages {
		selected[name] = true
	}
	var names []string
	for _, pkg := range packages {
		if len(selected) != 0 && !selected[pkg.Name] {
			continue
		}
		for name := range pkg.Slices {
			names = append(names, pkg.Name+"/"+name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if _, writeErr := fmt.Fprintln(out, name); writeErr != nil {
			return writeErr
		}
	}
	return nil
}

func newSlicesShowCommand(options *slicesOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show PACKAGE/SLICE",
		Short: "Show one slice definition",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			packages, err := options.load()
			if err != nil {
				return err
			}
			packageName, sliceName, ok := strings.Cut(args[0], "/")
			if !ok || packageName == "" || sliceName == "" {
				return errors.New("slice must be written as PACKAGE/SLICE")
			}
			pkg, ok := packages[packageName]
			if !ok {
				return fmt.Errorf("package %q not found", packageName)
			}
			slice, ok := pkg.Slices[sliceName]
			if !ok {
				return fmt.Errorf("slice %q not found in package %q", sliceName, packageName)
			}
			return writeSlice(cmd.OutOrStdout(), pkg, &slice)
		},
	}
}

func newSlicesCheckCommand(options *slicesOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate a whole catalogue",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if options.catalogue == "" {
				return errors.New("--catalogue is required")
			}
			fsys, closeFS, metadata, err := options.loadFilesystem()
			if err != nil {
				return fmt.Errorf("%w: %v", errOperation, err)
			}
			defer closeFS()
			diagnostics := slicespkg.CheckPackages(fsys, metadata, slicespkg.CheckDiagnosticLimit)
			if len(diagnostics) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "catalogue OK")
				return err
			}
			lines := make([]string, 0, len(diagnostics))
			for _, diagnostic := range diagnostics {
				lines = append(lines, diagnostic.Error())
			}
			return fmt.Errorf("%w: catalogue check failed:\n%s", errOperation, strings.Join(lines, "\n"))
		},
	}
}

func (options *slicesOptions) load() (map[string]*slicespkg.Package, error) {
	if options.catalogue == "" {
		return nil, errors.New("--catalogue is required")
	}
	fsys, closeFS, metadata, err := options.loadFilesystem()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errOperation, err)
	}
	defer closeFS()
	packages, err := slicespkg.ParsePackages(fsys, metadata)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errOperation, err)
	}
	return packages, nil
}

// loadFilesystem reads the catalogue with the snapshot's own reader: confined to
// the directory and bounded per file, so inspection needs no lock or network.
func (options *slicesOptions) loadFilesystem() (fs.FS, func(), *slicespkg.Catalogue, error) {
	directory, err := catalogue.OpenDirectory(options.catalogue)
	if err != nil {
		return nil, nil, nil, err
	}
	data, err := fs.ReadFile(directory, "chisel.yaml")
	if err != nil {
		_ = directory.Close()
		return nil, nil, nil, fmt.Errorf("read catalogue metadata: %w", err)
	}
	metadata, err := slicespkg.ParseCatalogue(data)
	if err != nil {
		_ = directory.Close()
		return nil, nil, nil, err
	}
	return directory, func() { _ = directory.Close() }, metadata, nil
}

func writeSlice(out io.Writer, pkg *slicespkg.Package, slice *slicespkg.Slice) error {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "package: %s\nslice: %s\n", pkg.Name, slice.Name)
	if slice.Hint != "" {
		fmt.Fprintf(&buffer, "hint: %s\n", slice.Hint)
	}
	if pkg.Archive != "" {
		fmt.Fprintf(&buffer, "archive: %s\n", pkg.Archive)
	}
	if pkg.Store != "" {
		fmt.Fprintf(&buffer, "store: %s\n", pkg.Store)
	}
	writeEssentials(&buffer, slice)
	writeContents(&buffer, slice)
	_, err := out.Write(buffer.Bytes())
	return err
}

func writeEssentials(out *bytes.Buffer, slice *slicespkg.Slice) {
	if len(slice.Essential) == 0 {
		return
	}
	fmt.Fprintln(out, "essential:")
	keys := make([]slicespkg.SliceKey, 0, len(slice.Essential))
	for key := range slice.Essential {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	for _, key := range keys {
		info := slice.Essential[key]
		fmt.Fprintf(out, "  %s", key)
		if len(info.Arch) != 0 {
			fmt.Fprintf(out, " [%s]", strings.Join(info.Arch, ", "))
		}
		fmt.Fprintln(out)
	}
}

func writeContents(out *bytes.Buffer, slice *slicespkg.Slice) {
	if len(slice.Contents) == 0 {
		return
	}
	fmt.Fprintln(out, "contents:")
	paths := make([]string, 0, len(slice.Contents))
	for path := range slice.Contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		info := slice.Contents[path]
		writePath(out, path, &info)
	}
}

func writePath(out *bytes.Buffer, path string, info *slicespkg.PathInfo) {
	fmt.Fprintf(out, "  %s %s %q", path, info.Kind, info.Info)
	if info.Mode != 0 {
		fmt.Fprintf(out, " mode=%04o", info.Mode)
	}
	if info.Mutable {
		fmt.Fprint(out, " mutable")
	}
	if len(info.Arch) != 0 {
		fmt.Fprintf(out, " [%s]", strings.Join(info.Arch, ", "))
	}
	fmt.Fprintln(out)
}
