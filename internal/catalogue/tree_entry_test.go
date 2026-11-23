package catalogue_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/catalogue"
)

func TestNewTree_RejectsInvalidEntries(t *testing.T) {
	t.Parallel()
	valid := catalogue.Entry{Path: "a", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64), Size: 1}
	cases := map[string][]catalogue.Entry{
		"empty path":       {{Path: "", Kind: catalogue.KindDir}},
		"absolute path":    {{Path: "/a", Kind: catalogue.KindDir}},
		"dot path":         {{Path: ".", Kind: catalogue.KindDir}},
		"dot segment":      {{Path: "a/./b", Kind: catalogue.KindDir}},
		"parent segment":   {{Path: "a/../b", Kind: catalogue.KindDir}},
		"backslash":        {{Path: `a\b`, Kind: catalogue.KindDir}},
		"nul":              {{Path: "a\x00b", Kind: catalogue.KindDir}},
		"invalid utf8":     {{Path: "a\xff", Kind: catalogue.KindDir}},
		"trailing slash":   {{Path: "a/", Kind: catalogue.KindDir}},
		"unknown kind":     {{Path: "a", Kind: "device"}},
		"dir metadata":     {{Path: "a", Kind: catalogue.KindDir, Size: 1}},
		"file target":      {{Path: "a", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64), Target: "x"}},
		"file sha short":   {{Path: "a", Kind: catalogue.KindFile, SHA256: "abc"}},
		"file sha upper":   {{Path: "a", Kind: catalogue.KindFile, SHA256: strings.Repeat("A", 64)}},
		"file negative":    {{Path: "a", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64), Size: -1}},
		"symlink metadata": {{Path: "a", Kind: catalogue.KindSymlink, Target: "b", SHA256: strings.Repeat("a", 64)}},
		"symlink empty":    {{Path: "a", Kind: catalogue.KindSymlink}},
		"symlink nul":      {{Path: "a", Kind: catalogue.KindSymlink, Target: "b\x00c"}},
		"duplicate":        {valid, valid},
		"parent file":      {{Path: "a", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64)}, {Path: "a/b", Kind: catalogue.KindDir}},
		"absolute target":  {{Path: "a", Kind: catalogue.KindSymlink, Target: "/etc/passwd"}},
		"escaping target":  {{Path: "a", Kind: catalogue.KindSymlink, Target: "../../etc/passwd"}},
		"ancestor target":  {{Path: "a/b", Kind: catalogue.KindSymlink, Target: ".."}},
		"self target":      {{Path: "a", Kind: catalogue.KindSymlink, Target: "a"}},
		"link cycle":       {{Path: "a", Kind: catalogue.KindSymlink, Target: "b"}, {Path: "b", Kind: catalogue.KindSymlink, Target: "a"}},
		"link under link":  {{Path: "a", Kind: catalogue.KindSymlink, Target: "b"}, {Path: "a/b", Kind: catalogue.KindFile, SHA256: strings.Repeat("a", 64)}},
		"component escape": {
			{Path: "d", Kind: catalogue.KindDir},
			{Path: "x", Kind: catalogue.KindDir},
			{Path: "d/s", Kind: catalogue.KindSymlink, Target: "../x"},
			{Path: "link", Kind: catalogue.KindSymlink, Target: "d/s/../../outside"},
		},
		"component cycle": {
			{Path: "a", Kind: catalogue.KindSymlink, Target: "b/c"},
			{Path: "b/c", Kind: catalogue.KindSymlink, Target: "../a"},
		},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := catalogue.NewTree(entries); err == nil {
				t.Fatal("invalid tree accepted")
			}
		})
	}
}
