package locking

import (
	"testing"

	"github.com/matt-mai/vapor/internal/schema/lock"
)

func TestUpdatesReportsOnlyNewerVersions(t *testing.T) {
	t.Parallel()
	locked := &lock.Lockfile{
		Packages: []lock.Package{
			{Platform: "linux/amd64", Name: "curl", Version: "8.5.0-2"},
			{Platform: "linux/amd64", Name: "same", Version: "1.0"},
			{Platform: "linux/amd64", Name: "older", Version: "2.0"},
			{Platform: "linux/amd64", Name: "gone", Version: "1.0"},
			{Platform: "linux/amd64", Name: "epoch", Version: "1:9.0"},
		},
		Slices: []lock.Slice{
			{Platform: "linux/arm64", Package: "base-files", Version: "13.8+deb13u1"},
		},
	}
	selected := []lock.Package{
		{Platform: "linux/amd64", Name: "curl", Version: "8.6.0-1"},
		{Platform: "linux/amd64", Name: "same", Version: "1.0"},
		{Platform: "linux/amd64", Name: "older", Version: "1.9"},
		{Platform: "linux/amd64", Name: "fresh", Version: "3.0"},
		{Platform: "linux/amd64", Name: "epoch", Version: "0:10.0"},
	}
	slices := []lock.Slice{
		{Platform: "linux/arm64", Package: "base-files", Version: "13.8+deb13u2"},
	}
	updates, err := Updates(locked, selected, slices)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"linux/amd64 package curl 8.5.0-2 -> 8.6.0-1",
		"linux/arm64 slice base-files 13.8+deb13u1 -> 13.8+deb13u2",
	}
	if len(updates) != len(want) {
		t.Fatalf("updates = %v, want %v", updates, want)
	}
	for i := range want {
		if got := updates[i].String(); got != want[i] {
			t.Fatalf("update %d = %q, want %q", i, got, want[i])
		}
	}
}

// TestUpdatesIgnoresUnparsableVersions keeps a payload-less probe honest: a version it
// cannot order must not trigger a rebuild.
func TestUpdatesIgnoresUnparsableVersions(t *testing.T) {
	t.Parallel()
	locked := &lock.Lockfile{
		Packages: []lock.Package{{Platform: "linux/amd64", Name: "odd", Version: "1.0"}},
	}
	selected := []lock.Package{{Platform: "linux/amd64", Name: "odd", Version: "not a version"}}
	updates, err := Updates(locked, selected, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 0 {
		t.Fatalf("updates = %v, want none", updates)
	}
}

func TestUpdatesRejectsNilLock(t *testing.T) {
	t.Parallel()
	if _, err := Updates(nil, nil, nil); err == nil {
		t.Fatal("nil lock accepted")
	}
}
