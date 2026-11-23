package slices_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func contentPackage(contents string) string {
	return "package: demo\nslices:\n  runtime:\n    contents:\n" + contents
}

func parseContent(t *testing.T, path, options string) (slices.PathInfo, error) {
	t.Helper()
	packages, err := parseSDFs(t, map[string]string{
		"slices/demo.yaml": contentPackage("      " + path + ": " + options + "\n"),
	})
	if err != nil {
		return slices.PathInfo{}, err
	}
	return packages["demo"].Slices["runtime"].Contents[path], nil
}

func TestParseContentsKinds(t *testing.T) {
	tests := []struct {
		name string
		path string
		opts string
		want slices.PathInfo
	}{
		{"implicit copy", "/demo", "{}", slices.PathInfo{Kind: slices.PathCopy}},
		{"null copy", "/demo", "", slices.PathInfo{Kind: slices.PathCopy}},
		{"same path copy", "/demo", "{copy: /demo}", slices.PathInfo{Kind: slices.PathCopy}},
		{"other copy", "/demo", "{copy: /src}", slices.PathInfo{Kind: slices.PathCopy, Info: "/src"}},
		{"empty text", "/demo", `{text: ""}`, slices.PathInfo{Kind: slices.PathText, Info: ""}},
		{"text", "/demo", `{text: "hello"}`,
			slices.PathInfo{Kind: slices.PathText, Info: "hello"}},
		{"symlink", "/demo", "{symlink: ../target}",
			slices.PathInfo{Kind: slices.PathSymlink, Info: "../target"}},
		{"directory", "/demo/", "{make: true, mode: 0750}",
			slices.PathInfo{Kind: slices.PathDir, Mode: 0o750}},
		{"file mode", "/demo", "{text: x, mode: 0644}",
			slices.PathInfo{Kind: slices.PathText, Info: "x", Mode: 0o644}},
		{"glob scalar arch", "/usr/lib/*.so", "{arch: ppc64el}",
			slices.PathInfo{Kind: slices.PathGlob, Arch: []string{"ppc64el"}}},
		{"duplicate arch", "/demo", "{arch: [amd64, amd64]}",
			slices.PathInfo{Kind: slices.PathCopy, Arch: []string{"amd64", "amd64"}}},
		{"glob list arch", "/usr/lib/*.so", "{arch: [amd64, arm64], until: mutate}",
			slices.PathInfo{Kind: slices.PathGlob, Arch: []string{"amd64", "arm64"}, Until: slices.UntilMutate}},
		{"generate", "/var/lib/chisel/**", "{generate: manifest}",
			slices.PathInfo{Kind: slices.PathGenerate, Generate: slices.GenerateManifest}},
		{"unknown generate", "/var/lib/chisel/**", "{generate: custom}",
			slices.PathInfo{Kind: slices.PathGenerate, Generate: "custom"}},
		{"prefer", "/demo", "{prefer: provider}", slices.PathInfo{Kind: slices.PathCopy, Prefer: "provider"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseContent(t, test.path, test.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != test.want.Kind || got.Info != test.want.Info || got.Mode != test.want.Mode ||
				got.Until != test.want.Until || got.Generate != test.want.Generate || got.Prefer != test.want.Prefer {
				t.Fatalf("info = %+v, want %+v", got, test.want)
			}
			if strings.Join(got.Arch, ",") != strings.Join(test.want.Arch, ",") {
				t.Fatalf("arch = %v, want %v", got.Arch, test.want.Arch)
			}
		})
	}
}

func TestParseContentsErrors(t *testing.T) {
	tests := []struct {
		name string
		path string
		opts string
		want string
	}{
		{"relative path", "demo", "{}", "not absolute"},
		{"unclean path", "/usr/../demo", "{}", "not clean"},
		{"root path", "/", "{}", "not clean"},
		{"make file", "/demo", "{make: true}", "must end in /"},
		{"make with copy", "/demo/", "{make: true, copy: /src}", "conflicting kinds"},
		{"text and symlink", "/demo", "{text: x, symlink: y}", "conflicting kinds"},
		{"copy and dir", "/demo/", "{copy: /src, make: true}", "conflicting kinds"},
		{"mutable copy directory", "/demo/", "{copy: /src, mutable: true}", "mutable is not a regular file"},
		{"mutable symlink", "/demo", "{symlink: x, mutable: true}", "mutable is not a regular file"},
		{"invalid until", "/demo", "{until: never}", "invalid until"},
		{"path arch invalid", "/demo", "{arch: mips64}", "invalid architecture"},
		{"path arch empty", "/demo", "{arch: []}", ""},
		{"prefer self", "/demo", "{prefer: demo}", "cannot prefer its own package"},
		{"generate with until", "/var/lib/chisel/**", "{generate: manifest, until: mutate}", "invalid generate options"},
		{"generate with mode", "/var/lib/chisel/**", "{generate: manifest, mode: 0644}", "invalid generate options"},
		{"generate with prefer", "/var/lib/chisel/**", "{generate: manifest, prefer: other}", "invalid generate options"},
		{"generate without suffix", "/var/lib/chisel", "{generate: manifest}", "does not end with /**"},
		{"generate inner glob", "/var/*/chisel/**", "{generate: manifest}", "wildcard characters"},
		{"glob with mode", "/usr/*", "{mode: 0644}", "invalid glob options"},
		{"glob with make", "/usr/*/", "{make: true}", "invalid glob options"},
		{"glob with prefer", "/usr/*", "{prefer: other}", "invalid glob options"},
		{"glob with text", "/usr/*", "{text: x}", "invalid glob options"},
		{"mode out of range", "/demo", "{text: x, mode: 010000}", "invalid mode"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseContent(t, test.path, test.opts)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
