package slices

import (
	"fmt"
	"path"
	"strings"
	"unicode"
)

func validatePackageTargets(raw *rawPackage, catalogue *Catalogue, pkg *Package) error {
	if raw.Store != "" {
		if err := applyPackageStore(raw, catalogue, pkg); err != nil {
			return err
		}
	} else if raw.DefaultTrack != "" {
		return fmt.Errorf("package %q sets default-track without a store", raw.Package)
	}
	if raw.Archive != "" {
		if _, ok := catalogue.Archives[raw.Archive]; !ok {
			return fmt.Errorf("package %q refers to undefined archive %q", raw.Package, raw.Archive)
		}
	}
	return nil
}

func applyPackageStore(raw *rawPackage, catalogue *Catalogue, pkg *Package) error {
	store, ok := catalogue.Stores[raw.Store]
	if !ok {
		return fmt.Errorf("package %q refers to undefined store %q", raw.Package, raw.Store)
	}
	if raw.Archive != "" {
		return fmt.Errorf("package %q sets both archive and store", raw.Package)
	}
	if raw.DefaultTrack == "" {
		return fmt.Errorf("package %q with a store requires default-track", raw.Package)
	}
	if strings.Contains(raw.DefaultTrack, "/") {
		return fmt.Errorf("package %q default-track must not contain /", raw.Package)
	}
	pkg.Name = store.DefaultPrefix + raw.Package
	return nil
}

func parseSlice(pkg *Package, name string, raw rawSlice, packageEssential map[SliceKey]EssentialInfo) (Slice, error) {
	if !sliceNamePattern.MatchString(name) {
		return Slice{}, fmt.Errorf("invalid slice name %q", name)
	}
	if len(raw.Hint) > MaxHintSize {
		return Slice{}, fmt.Errorf("slice %s_%s hint exceeds %d bytes", pkg.Name, name, MaxHintSize)
	}
	for _, char := range raw.Hint {
		if !unicode.IsPrint(char) {
			return Slice{}, fmt.Errorf("slice %s_%s hint contains a non-printable character", pkg.Name, name)
		}
	}
	sliceEssential, err := parseEssentials(raw.Essential)
	if err != nil {
		return Slice{}, err
	}
	essential, err := mergeEssentials(pkg.Name, name, packageEssential, sliceEssential)
	if err != nil {
		return Slice{}, err
	}
	contents, err := parseContents(pkg.Name, name, raw.Contents)
	if err != nil {
		return Slice{}, err
	}
	return Slice{
		Package:   pkg.Name,
		Name:      name,
		Hint:      raw.Hint,
		Essential: essential,
		Contents:  contents,
		Mutate:    raw.Mutate,
	}, nil
}

func parseEssentials(raw rawEssentialMap) (map[SliceKey]EssentialInfo, error) {
	essential := make(map[SliceKey]EssentialInfo, len(raw))
	for _, ref := range sortedKeys(raw) {
		key, err := parseSliceKey(ref)
		if err != nil {
			return nil, err
		}
		var arches []string
		if raw[ref] != nil {
			arches = append([]string(nil), raw[ref].Arch.Values...)
		}
		essential[key] = EssentialInfo{Arch: arches}
	}
	return essential, nil
}

func mergeEssentials(
	pkgName, sliceName string,
	packageEssential, sliceEssential map[SliceKey]EssentialInfo,
) (map[SliceKey]EssentialInfo, error) {
	merged := make(map[SliceKey]EssentialInfo, len(packageEssential)+len(sliceEssential))
	for key, info := range packageEssential {
		if key.Package == pkgName && key.Slice == sliceName {
			continue
		}
		merged[key] = info
	}
	for key, info := range sliceEssential {
		if key.Package == pkgName && key.Slice == sliceName {
			return nil, fmt.Errorf("slice %s_%s cannot be essential to itself", pkgName, sliceName)
		}
		if _, ok := merged[key]; ok {
			return nil, fmt.Errorf("slice %s_%s repeats %s in essential fields", pkgName, sliceName, key)
		}
		merged[key] = info
	}
	return merged, nil
}

func parseSliceKey(ref string) (SliceKey, error) {
	pkgName, sliceName, ok := strings.Cut(ref, "_")
	if !ok || !packageNamePattern.MatchString(pkgName) || !sliceNamePattern.MatchString(sliceName) {
		return SliceKey{}, fmt.Errorf("invalid essential slice reference %q", ref)
	}
	return SliceKey{Package: pkgName, Slice: sliceName}, nil
}

func validateArchList(arches []string) error {
	for _, arch := range arches {
		if !catalogueArchitectures[arch] {
			return fmt.Errorf("path architecture contains invalid architecture %q", arch)
		}
	}
	return nil
}

func validContentPath(value string) (bool, error) {
	if !path.IsAbs(value) {
		return false, fmt.Errorf("content path %q is not absolute", value)
	}
	isDir := strings.HasSuffix(value, "/")
	compare := value
	if isDir {
		compare = strings.TrimSuffix(compare, "/")
	}
	if path.Clean(value) != compare {
		return false, fmt.Errorf("content path %q is not clean", value)
	}
	return isDir, nil
}
