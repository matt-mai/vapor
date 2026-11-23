package synthesis

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// Timezone state locations. An image names its zone with /etc/timezone and
// points /etc/localtime at the compiled zone data.
const (
	LocaltimePath  = "/etc/localtime"
	TimezonePath   = "/etc/timezone"
	ZoneinfoPrefix = "/usr/share/zoneinfo/"
)

// EtcUTCTimezone is the alias tzdata publishes for UTC. It names the same fixed
// data, so it is treated identically.
const EtcUTCTimezone = "Etc/UTC"

// UTCTimezone is the zone synthesis supplies when the specification and the
// selected packages both leave the timezone unset.
const UTCTimezone = "UTC"

// TimezoneOrigin attributes synthesized timezone state to the specification.
var TimezoneOrigin = vfs.Origin{Path: "filesystem.timezone"}

// utcZoneinfo is the compiled zone data for UTC, which needs no selected input
// because the encoding is fixed by the format rather than by the zone database.
// It is the value tzdata ships for Etc/UTC.
var utcZoneinfo = []byte{
	0x54, 0x5a, 0x69, 0x66, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x54, 0x43, 0x00, 0x54, 0x5a, 0x69, 0x66, 0x32,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x55, 0x54, 0x43, 0x00, 0x0a, 0x55, 0x54, 0x43, 0x30, 0x0a,
}

// Timezone applies the declared zone, or preserves selected state, or supplies
// UTC. A non-UTC zone must already be present in the image: reading host
// zoneinfo would make the output depend on the build machine.
func Timezone(tree *vfs.Tree, declared *string) error {
	if tree == nil {
		return errors.New("timezone synthesis requires an image tree")
	}
	zone := ""
	if declared != nil {
		zone = *declared
	}
	if zone == "" {
		selected, err := selectedTimezone(tree)
		if err != nil {
			return err
		}
		if selected != "" {
			return nil
		}
		zone = UTCTimezone
	}
	if err := validateZone(zone); err != nil {
		return err
	}
	zoneinfo, err := zoneData(tree, zone)
	if err != nil {
		return err
	}
	return writeTimezone(tree, zone, zoneinfo)
}

// selectedTimezone reports the zone the image already declares, so an omitted
// specification setting preserves it. A file that exists but cannot be read
// fails rather than looking undeclared, which would silently switch the image to
// UTC.
func selectedTimezone(tree *vfs.Tree) (string, error) {
	content, err := tree.Read(TimezonePath)
	if err == nil {
		if zone := strings.TrimSpace(string(content)); zone != "" {
			return zone, nil
		}
		// An empty or whitespace-only name declares nothing, so the selected
		// localtime still decides; returning here would replace it with UTC.
	} else if !errors.Is(err, vfs.ErrNotExist) {
		return "", fmt.Errorf("%s cannot be read: %w", TimezonePath, err)
	}
	entry, ok := tree.Lookup(LocaltimePath)
	if !ok {
		return "", nil
	}
	if entry.Kind == vfs.File {
		// A selected regular localtime carries its own zone data, so there is no
		// zone name to report but the state is still the image's. Reporting nothing
		// would replace it with UTC.
		return selectedLocaltime, nil
	}
	if entry.Kind != vfs.Symlink {
		return "", nil
	}
	return strings.TrimPrefix(entry.Target, ZoneinfoPrefix), nil
}

// selectedLocaltime reports a localtime file the image already provides. It is not
// a zone name, so it only ever means "leave the selected state alone".
const selectedLocaltime = "\x00selected"

// validateZone rejects a zone name that could not name a file under zoneinfo.
func validateZone(zone string) error {
	if zone == "" || path.IsAbs(zone) || path.Clean(zone) != zone || strings.ContainsAny(zone, "\\\x00") {
		return fmt.Errorf("timezone %q is not a zone name", zone)
	}
	for component := range strings.SplitSeq(zone, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("timezone %q is not a zone name", zone)
		}
	}
	return nil
}

// embeddedZone reports whether a zone's compiled data is encoded in this binary,
// and returns it. UTC and its Etc alias are the same fixed data, so an image can
// declare either without selecting tzdata; every other zone must come from
// selected verified zoneinfo.
func embeddedZone(zone string) ([]byte, bool) {
	if zone == UTCTimezone || zone == EtcUTCTimezone {
		return utcZoneinfo, true
	}
	return nil, false
}

// zoneData returns the compiled zone data for a zone.
//
// The zone name is resolved through the tree first, because tzdata publishes many
// names as links to another zone rather than as a second copy of the data.
func zoneData(tree *vfs.Tree, zone string) ([]byte, error) {
	if content, ok := embeddedZone(zone); ok {
		return content, nil
	}
	resolved, err := tree.Resolve(ZoneinfoPrefix + zone)
	if err != nil {
		return nil, fmt.Errorf("timezone %q needs selected zoneinfo at %s%s", zone, ZoneinfoPrefix, zone)
	}
	content, err := tree.Read(resolved)
	if err != nil {
		return nil, fmt.Errorf("timezone %q needs selected zoneinfo at %s%s", zone, ZoneinfoPrefix, zone)
	}
	if !bytes.HasPrefix(content, []byte("TZif")) {
		return nil, fmt.Errorf("zoneinfo for %q is not compiled zone data", zone)
	}
	return content, nil
}

// writeTimezone sets /etc/timezone and makes /etc/localtime point at the zone
// file, which is how every supported distribution represents the setting.
func writeTimezone(tree *vfs.Tree, zone string, zoneinfo []byte) error {
	// Both destinations are checked before either is written, so a refused
	// localtime cannot leave a new zone name behind.
	for _, location := range []string{TimezonePath, LocaltimePath} {
		if err := replaceable(tree, location); err != nil {
			return err
		}
	}
	if err := writeTimezoneName(tree, zone); err != nil {
		return err
	}
	// An embedded zone has no selected file to point at, so its data is written
	// directly rather than linked to a path the image may not contain.
	if _, ok := embeddedZone(zone); ok {
		return writeFile(tree, LocaltimePath, zoneinfo, TimezoneOrigin)
	}
	return replaceWithSymlink(tree, LocaltimePath, ZoneinfoPrefix+zone, TimezoneOrigin)
}

func writeTimezoneName(tree *vfs.Tree, zone string) error {
	return writeFile(tree, TimezonePath, []byte(zone+"\n"), TimezoneOrigin)
}
