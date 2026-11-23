package synthesis_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/synthesis"
	"github.com/matt-mai/vapor/internal/vfs"
)

const berlinZone = "Europe/Berlin"

func treeWithZoneinfo(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	if err := tree.Dir("/usr/share/zoneinfo/Europe", vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("dir: %v", err)
	}
	zoneinfo := append([]byte("TZif"), berlinZone...)
	if err := tree.File("/usr/share/zoneinfo/"+berlinZone, zoneinfo, vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("zoneinfo: %v", err)
	}
	return tree
}

func TestTimezone_SuppliesUTCWhenOmitted(t *testing.T) {
	tree := vfs.New()
	if err := synthesis.Timezone(tree, nil); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	if content := readFile(t, tree, synthesis.TimezonePath); content != "UTC\n" {
		t.Fatalf("timezone = %q", content)
	}
	entry, ok := tree.Lookup(synthesis.LocaltimePath)
	if !ok || entry.Kind != vfs.File {
		t.Fatalf("localtime = %+v", entry)
	}
	data, err := tree.Read(synthesis.LocaltimePath)
	if err != nil || !strings.HasPrefix(string(data), "TZif") {
		t.Fatalf("localtime data = %q, err = %v", data, err)
	}
}

func TestTimezone_PreservesSelectedState(t *testing.T) {
	tree := treeWithZoneinfo(t)
	if err := tree.File(synthesis.TimezonePath, []byte("Europe/Berlin\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("timezone file: %v", err)
	}
	if err := synthesis.Timezone(tree, nil); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	if content := readFile(t, tree, synthesis.TimezonePath); content != "Europe/Berlin\n" {
		t.Fatalf("timezone = %q", content)
	}
	if _, ok := tree.Lookup(synthesis.LocaltimePath); ok {
		t.Fatal("localtime was created despite selected state")
	}
}

// A selected regular localtime is the image's timezone state. Omission must
// preserve it rather than replace it with UTC.
func TestTimezone_PreservesSelectedLocaltimeFile(t *testing.T) {
	tree := vfs.New()
	if err := tree.File(synthesis.LocaltimePath, []byte("TZif-selected"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("localtime: %v", err)
	}
	if err := synthesis.Timezone(tree, nil); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	if content := readFile(t, tree, synthesis.LocaltimePath); content != "TZif-selected" {
		t.Fatalf("localtime = %q", content)
	}
	if _, ok := tree.Lookup(synthesis.TimezonePath); ok {
		t.Fatal("timezone name was created despite selected localtime")
	}
}

// An empty selected name declares nothing, so the selected localtime still
// decides. Reading it as "unset" would replace the selected state with UTC.
func TestTimezone_PreservesSelectedLocaltimeBehindAnEmptyName(t *testing.T) {
	for name, content := range map[string]string{"empty": "", "whitespace": " \n\t\n"} {
		t.Run(name, func(t *testing.T) {
			tree := vfs.New()
			if err := tree.File(synthesis.TimezonePath, []byte(content), vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatalf("timezone: %v", err)
			}
			if err := tree.File(synthesis.LocaltimePath, []byte("TZif-selected"),
				vfs.Attrs{Mode: 0o644}); err != nil {
				t.Fatalf("localtime: %v", err)
			}
			if err := synthesis.Timezone(tree, nil); err != nil {
				t.Fatalf("timezone: %v", err)
			}
			if got := readFile(t, tree, synthesis.LocaltimePath); got != "TZif-selected" {
				t.Fatalf("localtime = %q", got)
			}
			if got := readFile(t, tree, synthesis.TimezonePath); got != content {
				t.Fatalf("timezone = %q", got)
			}
		})
	}
}

// Replacing a directory that still holds entries would leave its children under a
// non-directory, which is not a filesystem tree. The refusal must not leave the
// other destination already rewritten.
func TestTimezone_RejectsReplacingANonemptyDirectory(t *testing.T) {
	tree := vfs.New()
	if err := tree.File(synthesis.TimezonePath, []byte(berlinZone+"\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	if err := tree.Dir(synthesis.LocaltimePath, vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("localtime: %v", err)
	}
	if err := tree.File(synthesis.LocaltimePath+"/child", []byte("x"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("child: %v", err)
	}
	zone := synthesis.UTCTimezone
	err := synthesis.Timezone(tree, &zone)
	if err == nil || !strings.Contains(err.Error(), "nonempty directory") {
		t.Fatalf("error = %v", err)
	}
	if entry, ok := tree.Lookup(synthesis.LocaltimePath); !ok || entry.Kind != vfs.Dir {
		t.Fatalf("localtime = %+v, ok = %v", entry, ok)
	}
	if got := readFile(t, tree, synthesis.TimezonePath); got != berlinZone+"\n" {
		t.Fatalf("timezone was rewritten to %q", got)
	}
}

func TestTimezone_LinksDeclaredZone(t *testing.T) {
	tree := treeWithZoneinfo(t)
	zone := berlinZone
	if err := synthesis.Timezone(tree, &zone); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	entry, ok := tree.Lookup(synthesis.LocaltimePath)
	if !ok || entry.Kind != vfs.Symlink {
		t.Fatalf("localtime = %+v", entry)
	}
	if entry.Target != "/usr/share/zoneinfo/Europe/Berlin" {
		t.Fatalf("target = %q", entry.Target)
	}
	if content := readFile(t, tree, synthesis.TimezonePath); content != "Europe/Berlin\n" {
		t.Fatalf("timezone = %q", content)
	}
}

func TestTimezone_RejectsMissingZoneinfo(t *testing.T) {
	zone := berlinZone
	err := synthesis.Timezone(vfs.New(), &zone)
	if err == nil || !strings.Contains(err.Error(), "needs selected zoneinfo") {
		t.Fatalf("error = %v", err)
	}
}

func TestTimezone_RejectsUncompiledZoneinfo(t *testing.T) {
	tree := vfs.New()
	if err := tree.File("/usr/share/zoneinfo/Europe/Berlin", []byte("not zone data"),
		vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("zoneinfo: %v", err)
	}
	zone := berlinZone
	err := synthesis.Timezone(tree, &zone)
	if err == nil || !strings.Contains(err.Error(), "not compiled zone data") {
		t.Fatalf("error = %v", err)
	}
}

func TestTimezone_RejectsInvalidZones(t *testing.T) {
	for _, zone := range []string{"/etc/passwd", "../etc/passwd", "Europe//Berlin", "Europe/./Berlin", "a\\b"} {
		t.Run(zone, func(t *testing.T) {
			declared := zone
			err := synthesis.Timezone(vfs.New(), &declared)
			if err == nil || !strings.Contains(err.Error(), "is not a zone name") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTimezone_ReplacesExistingLocaltime(t *testing.T) {
	tree := treeWithZoneinfo(t)
	if err := tree.File(synthesis.LocaltimePath, []byte("stale"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("localtime: %v", err)
	}
	zone := berlinZone
	if err := synthesis.Timezone(tree, &zone); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	entry, ok := tree.Lookup(synthesis.LocaltimePath)
	if !ok || entry.Kind != vfs.Symlink {
		t.Fatalf("localtime = %+v", entry)
	}
}

// TestTimezone_EmbeddedZonesAreWrittenDirectly covers UTC and its Etc alias: both
// name the same fixed data, so neither may link to a zoneinfo file the image is
// not required to contain.
func TestTimezone_EmbeddedZonesAreWrittenDirectly(t *testing.T) {
	for _, zone := range []string{"UTC", "Etc/UTC"} {
		t.Run(zone, func(t *testing.T) {
			tree := vfs.New()
			if err := synthesis.Timezone(tree, &zone); err != nil {
				t.Fatalf("timezone: %v", err)
			}
			if content := readFile(t, tree, synthesis.TimezonePath); content != zone+"\n" {
				t.Fatalf("timezone = %q, want %q", content, zone+"\n")
			}
			entry, ok := tree.Lookup(synthesis.LocaltimePath)
			if !ok || entry.Kind != vfs.File {
				t.Fatalf("localtime = %+v, want a regular file", entry)
			}
			if content := readFile(t, tree, synthesis.LocaltimePath); !strings.HasPrefix(content, "TZif") {
				t.Fatalf("localtime is not compiled zone data: %q", content)
			}
		})
	}
}

// TestTimezone_FailsOnUnreadableSelectedFile guards against silently falling back
// to UTC when the image's timezone file exists but cannot be read.
func TestTimezone_FailsOnUnreadableSelectedFile(t *testing.T) {
	tree := treeWithZoneinfo(t)
	if err := tree.Dir(synthesis.TimezonePath, vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	err := synthesis.Timezone(tree, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("error %v does not report the unreadable timezone file", err)
	}
}

func TestTimezone_RequiresTree(t *testing.T) {
	if err := synthesis.Timezone(nil, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestTimezone_ReplacesExistingTimezoneFile(t *testing.T) {
	tree := treeWithZoneinfo(t)
	if err := tree.File(synthesis.TimezonePath, []byte("America/New_York\n"), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("timezone file: %v", err)
	}
	zone := berlinZone
	if err := synthesis.Timezone(tree, &zone); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	if content := readFile(t, tree, synthesis.TimezonePath); content != "Europe/Berlin\n" {
		t.Fatalf("timezone = %q", content)
	}
}

func TestTimezone_KeepsMatchingLocaltimeLink(t *testing.T) {
	tree := treeWithZoneinfo(t)
	if err := tree.Symlink(synthesis.LocaltimePath, "/usr/share/zoneinfo/Europe/Berlin", vfs.Attrs{}); err != nil {
		t.Fatalf("localtime: %v", err)
	}
	zone := berlinZone
	if err := synthesis.Timezone(tree, &zone); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	entry, ok := tree.Lookup(synthesis.LocaltimePath)
	if !ok || entry.Target != "/usr/share/zoneinfo/Europe/Berlin" {
		t.Fatalf("localtime = %+v", entry)
	}
}

func TestTimezone_ReplacesDifferentLocaltimeLink(t *testing.T) {
	tree := treeWithZoneinfo(t)
	if err := tree.Symlink(synthesis.LocaltimePath, "/usr/share/zoneinfo/Europe/London", vfs.Attrs{}); err != nil {
		t.Fatalf("localtime: %v", err)
	}
	zone := berlinZone
	if err := synthesis.Timezone(tree, &zone); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	entry, _ := tree.Lookup(synthesis.LocaltimePath)
	if entry.Target != "/usr/share/zoneinfo/Europe/Berlin" {
		t.Fatalf("target = %q", entry.Target)
	}
}

func TestTimezone_PreservesSelectedLink(t *testing.T) {
	tree := treeWithZoneinfo(t)
	if err := tree.Symlink(synthesis.LocaltimePath, "/usr/share/zoneinfo/Europe/Berlin", vfs.Attrs{}); err != nil {
		t.Fatalf("localtime: %v", err)
	}
	if err := synthesis.Timezone(tree, nil); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	if _, ok := tree.Lookup(synthesis.TimezonePath); ok {
		t.Fatal("timezone file was created despite selected link")
	}
}

func TestTimezone_FollowsLinkedZoneName(t *testing.T) {
	// tzdata publishes many names as links to another zone rather than as a
	// second copy of the data, so a declared alias must resolve.
	tree := vfs.New()
	if err := tree.Dir("/usr/share/zoneinfo/Africa", vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("dir: %v", err)
	}
	zoneinfo := append([]byte("TZif"), []byte("Bamako")...)
	if err := tree.File("/usr/share/zoneinfo/Africa/Bamako", zoneinfo, vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatalf("zoneinfo: %v", err)
	}
	if err := tree.Symlink("/usr/share/zoneinfo/Africa/Timbuktu", "Bamako", vfs.Attrs{}); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	zone := "Africa/Timbuktu"
	if err := synthesis.Timezone(tree, &zone); err != nil {
		t.Fatalf("timezone: %v", err)
	}
	entry, ok := tree.Lookup(synthesis.LocaltimePath)
	if !ok || entry.Target != "/usr/share/zoneinfo/Africa/Timbuktu" {
		t.Fatalf("localtime = %+v", entry)
	}
}

func TestTimezone_RejectsEscapingZoneLink(t *testing.T) {
	tree := vfs.New()
	if err := tree.Dir("/usr/share/zoneinfo/Europe", vfs.Attrs{Mode: 0o755}); err != nil {
		t.Fatalf("dir: %v", err)
	}
	if err := tree.Symlink("/usr/share/zoneinfo/Europe/Berlin", "../../../../etc/shadow", vfs.Attrs{}); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	zone := berlinZone
	err := synthesis.Timezone(tree, &zone)
	if err == nil || !strings.Contains(err.Error(), "needs selected zoneinfo") {
		t.Fatalf("error = %v", err)
	}
}
