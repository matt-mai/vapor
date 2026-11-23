package slices

import (
	"strings"
	"testing"
)

func fixturePackage(name string, slices ...Slice) *Package {
	pkg := &Package{RealName: name, Name: name, Slices: make(map[string]Slice)}
	for _, slice := range slices {
		slice.Package = name
		pkg.Slices[slice.Name] = slice
	}
	return pkg
}

func fixtureSlice(name string, contents map[string]PathInfo, essential ...SliceKey) Slice {
	slice := Slice{Name: name, Contents: contents}
	if len(essential) > 0 {
		slice.Essential = make(map[SliceKey]EssentialInfo)
		for _, key := range essential {
			slice.Essential[key] = EssentialInfo{}
		}
	}
	return slice
}

func copyPath(target string) PathInfo { return PathInfo{Kind: PathCopy, Info: target} }
func textPath(text string) PathInfo   { return PathInfo{Kind: PathText, Info: text} }
func globPath(path string) PathInfo   { return PathInfo{Kind: PathGlob, Info: path} }
func symlinkPath(target string) PathInfo {
	return PathInfo{Kind: PathSymlink, Info: target}
}

func TestValidatePackagesEssentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		packages map[string]*Package
		want     string
	}{
		{
			name: "valid graph",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", nil, SliceKey{"b", "two"})),
				"b": fixturePackage("b", fixtureSlice("two", nil)),
			},
		},
		{
			name: "missing slice",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", nil, SliceKey{"b", "missing"})),
				"b": fixturePackage("b", fixtureSlice("two", nil)),
			},
			want: "a_one requires b_missing, but slice is missing",
		},
		{
			name: "missing package",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", nil, SliceKey{"z", "one"})),
			},
			want: "a_one requires z_one, but slice is missing",
		},
		{
			name: "architecture-hidden cycle",
			packages: map[string]*Package{
				"a": fixturePackage("a", Slice{
					Name:      "one",
					Contents:  nil,
					Essential: map[SliceKey]EssentialInfo{{"b", "two"}: {Arch: []string{"amd64"}}},
				}),
				"b": fixturePackage("b", Slice{
					Name:      "two",
					Contents:  nil,
					Essential: map[SliceKey]EssentialInfo{{"a", "one"}: {Arch: []string{"arm64"}}},
				}),
			},
			want: "essential loop detected",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePackages(test.packages)
			if test.want == "" {
				if err != nil {
					t.Fatalf("ValidatePackages() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidatePackages() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidatePackagesPreferences(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		packages map[string]*Package
		want     string
	}{
		{
			name: "chain resolves conflict",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": withPrefer(textPath("one"), "b")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": withPrefer(textPath("two"), "c")}, SliceKey{"c", "three"})),
				"c": fixturePackage("c", fixtureSlice("three", map[string]PathInfo{"/x": textPath("three")})),
			},
		},
		{
			name: "undefined target",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": withPrefer(textPath("one"), "missing")})),
			},
			want: "refers to undefined package",
		},
		{
			name: "target lacks path",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": withPrefer(textPath("one"), "b")})),
				"b": fixturePackage("b", fixtureSlice("two", nil)),
			},
			want: "does not contain path /x",
		},
		{
			name: "prefer cycle",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": withPrefer(textPath("one"), "b")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": withPrefer(textPath("two"), "a")})),
			},
			want: "prefer loop",
		},
		{
			name: "two sources prefer one target",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": withPrefer(textPath("one"), "c")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": withPrefer(textPath("two"), "c")})),
				"c": fixturePackage("c", fixtureSlice("three", map[string]PathInfo{"/x": textPath("three")})),
			},
			want: "cannot both prefer",
		},
		{
			name: "conflicting targets from one package",
			packages: map[string]*Package{
				"a": fixturePackage("a",
					fixtureSlice("one", map[string]PathInfo{"/x": withPrefer(textPath("one"), "b")}),
					fixtureSlice("two", map[string]PathInfo{"/x": withPrefer(textPath("one"), "c")}),
				),
				"b": fixturePackage("b", fixtureSlice("three", map[string]PathInfo{"/x": textPath("b")})),
				"c": fixturePackage("c", fixtureSlice("four", map[string]PathInfo{"/x": textPath("c")})),
			},
			want: "has conflicting prefers",
		},
		{
			name: "no relation with prefer",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": withPrefer(textPath("one"), "c")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": textPath("two")})),
				"c": fixturePackage("c", fixtureSlice("three", map[string]PathInfo{"/x": textPath("three")})),
			},
			want: "conflict on /x without prefer relationship",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePackages(test.packages)
			if test.want == "" {
				if err != nil {
					t.Fatalf("ValidatePackages() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidatePackages() = %v, want %q", err, test.want)
			}
		})
	}
}

func withPrefer(info PathInfo, target string) PathInfo {
	info.Prefer = target
	return info
}

func TestValidatePackagesPathConflicts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		packages map[string]*Package
		want     string
	}{
		{
			name: "same generated content allowed",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": textPath("same")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": textPath("same")})),
			},
		},
		{
			name: "same symlink target allowed",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": symlinkPath("/target")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": symlinkPath("/target")})),
			},
		},
		{
			name: "different text",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": textPath("one")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": textPath("two")})),
			},
			want: "slices a_one and b_two conflict on /x",
		},
		{
			name: "same copy across packages",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x": copyPath("/x")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x": copyPath("/x")})),
			},
			want: "conflict on /x",
		},
		{
			name: "different copy within package",
			packages: map[string]*Package{
				"a": fixturePackage("a",
					fixtureSlice("one", map[string]PathInfo{"/x": copyPath("/one")}),
					fixtureSlice("two", map[string]PathInfo{"/x": copyPath("/two")}),
				),
			},
			want: "conflict on /x",
		},
		{
			name: "same copy within package",
			packages: map[string]*Package{
				"a": fixturePackage("a",
					fixtureSlice("one", map[string]PathInfo{"/x": copyPath("/x")}),
					fixtureSlice("two", map[string]PathInfo{"/x": copyPath("/x")}),
				),
			},
		},
		{
			name: "glob and same-package copy",
			packages: map[string]*Package{
				"a": fixturePackage("a",
					fixtureSlice("one", map[string]PathInfo{"/x/*": globPath("/x/*")}),
					fixtureSlice("two", map[string]PathInfo{"/x/y": copyPath("/x/y")}),
				),
			},
		},
		{
			name: "glob and other package exact",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x/*": globPath("/x/*")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x/y": copyPath("/x/y")})),
			},
			want: "conflict on /x/* and /x/y",
		},
		{
			name: "two overlapping globs",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x/*": globPath("/x/*")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/x/**": globPath("/x/**")})),
			},
			want: "conflict on /x/* and /x/**",
		},
		{
			name: "overlapping generators conflict",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{
					"/var/lib/chisel/**":        {Kind: PathGenerate, Generate: GenerateManifest},
					"/var/lib/chisel/nested/**": {Kind: PathGenerate, Generate: GenerateManifest},
				})),
			},
			want: "conflict on /var/lib/chisel/** and /var/lib/chisel/nested/**",
		},
		{
			name: "glob without overlap",
			packages: map[string]*Package{
				"a": fixturePackage("a", fixtureSlice("one", map[string]PathInfo{"/x/*": globPath("/x/*")})),
				"b": fixturePackage("b", fixtureSlice("two", map[string]PathInfo{"/y/z": copyPath("/y/z")})),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePackages(test.packages)
			if test.want == "" {
				if err != nil {
					t.Fatalf("ValidatePackages() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidatePackages() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGlobIntersects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		first, second string
		want          bool
	}{
		{"/x/*", "/x/y", true},
		{"/x/*", "/x/y/z", false},
		{"/x/**", "/x/y/z", true},
		{"/x/**/z", "/x/y/z", true},
		{"/x/*/z", "/x/y/z", true},
		{"/x/?", "/x/y", true},
		{"/x/?", "/x/yy", false},
		{"/x/*", "/x/**", true},
		{"/x/a*", "/x/*b", true},
		{"/x/a*", "/x/b*", false},
		{"/x/*", "/y/*", false},
	}
	for _, test := range tests {
		if got := globIntersects(test.first, test.second); got != test.want {
			t.Errorf("globIntersects(%q, %q) = %v, want %v", test.first, test.second, got, test.want)
		}
	}
}

func TestGlobIntersectsAdversarial(t *testing.T) {
	t.Parallel()
	for _, questions := range []int{16, 24} {
		first := "/*a" + strings.Repeat("?", questions) + "x"
		second := "/*a" + strings.Repeat("?", questions) + "y"
		if globIntersects(first, second) {
			t.Fatalf("globIntersects(%q, %q) = true", first, second)
		}
	}
}
