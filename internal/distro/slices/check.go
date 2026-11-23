package slices

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// CheckDiagnosticLimit is the default number of catalogue diagnostics retained.
const CheckDiagnosticLimit = 20

// CheckPackages parses every slice definition and validates the resulting
// catalogue, collecting independent file diagnostics instead of stopping at the
// first malformed file. Graph validation still runs only when all files parsed.
func CheckPackages(fsys fs.FS, catalogue *Catalogue, limit int) []error {
	if fsys == nil {
		return []error{errors.New("slice definition filesystem must not be nil")}
	}
	if catalogue == nil {
		return []error{errors.New("catalogue metadata must not be nil")}
	}
	if limit <= 0 {
		limit = CheckDiagnosticLimit
	}
	packages := make(map[string]*Package)
	collected := &diagnostics{limit: limit}
	checkSDFDirectory(fsys, "slices", catalogue, packages, collected)
	if info, err := fs.Stat(fsys, "bin-slices"); err == nil {
		if info.IsDir() {
			checkSDFDirectory(fsys, "bin-slices", catalogue, packages, collected)
		} else {
			collected.add(errors.New("read bin-slices directory failed"))
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		collected.add(errors.New("read bin-slices directory failed"))
	}
	if collected.total == 0 {
		if err := ValidatePackages(packages); err != nil {
			collected.add(err)
		}
	}
	return collected.result()
}

// diagnostics keeps at most limit entries so a catalogue that fails everywhere
// cannot make the walk retain an unbounded list.
type diagnostics struct {
	limit int
	items []error
	total int
}

func (d *diagnostics) add(err error) {
	d.total++
	if len(d.items) < d.limit {
		d.items = append(d.items, err)
	}
}

func (d *diagnostics) result() []error {
	if d.total > d.limit {
		return append(d.items, fmt.Errorf("%d more diagnostics omitted", d.total-d.limit))
	}
	return d.items
}

func checkSDFDirectory(fsys fs.FS, dir string, catalogue *Catalogue, packages map[string]*Package,
	collected *diagnostics) {
	info, err := fs.Stat(fsys, dir)
	if err != nil || !info.IsDir() {
		collected.add(fmt.Errorf("read %s directory failed", dir))
		return
	}
	walkErr := fs.WalkDir(fsys, dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			collected.add(fmt.Errorf("read %s directory failed", dir))
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			return nil
		}
		if diagnostic := checkSDFFile(fsys, name, entry.Name(), catalogue, packages); diagnostic != nil {
			collected.add(diagnostic)
		}
		return nil
	})
	if walkErr != nil {
		collected.add(fmt.Errorf("read %s directory failed", dir))
	}
}

func checkSDFFile(fsys fs.FS, name, baseName string, catalogue *Catalogue, packages map[string]*Package) error {
	base := strings.TrimSuffix(baseName, ".yaml")
	if !packageNamePattern.MatchString(base) {
		return fmt.Errorf("invalid slice definition filename %q", baseName)
	}
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return fmt.Errorf("%s: read slice definition file failed", name)
	}
	pkg, err := parsePackage(data, base, name, catalogue)
	if err != nil {
		return err
	}
	if previous, ok := packages[pkg.Name]; ok {
		return fmt.Errorf("package %q is defined more than once: %s and %s", pkg.Name, previous.Path, pkg.Path)
	}
	packages[pkg.Name] = pkg
	return nil
}
