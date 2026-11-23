package deb_test

import (
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		value string
		want  deb.Version
	}{
		{"0", deb.Version{Upstream: "0"}},
		{"1.0", deb.Version{Upstream: "1.0"}},
		{"1.0-1", deb.Version{Upstream: "1.0", Revision: "1"}},
		{"1:1.0-1", deb.Version{Epoch: 1, Upstream: "1.0", Revision: "1"}},
		{"01:1.0", deb.Version{Epoch: 1, Upstream: "1.0"}},
		{"1.0-1-2", deb.Version{Upstream: "1.0-1", Revision: "2"}},
		{"1:1.0:2-1", deb.Version{Epoch: 1, Upstream: "1.0:2", Revision: "1"}},
		{"1.0+git20240101-1~bpo1", deb.Version{Upstream: "1.0+git20240101", Revision: "1~bpo1"}},
		{"1.0-1+b1", deb.Version{Upstream: "1.0", Revision: "1+b1"}},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := deb.ParseVersion(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ParseVersion(%q) = %+v, want %+v", test.value, got, test.want)
			}
		})
	}
}

func TestParseVersionMalformed(t *testing.T) {
	for _, value := range []string{
		"",
		":1.0",
		"1:",
		"1.0-",
		"v1.0",
		"1_0",
		"1.0:2",
		"1.0-1_2",
		"1.0 2",
		"-1.0",
		"18446744073709551616:1",
		"1.0\n",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := deb.ParseVersion(value); err == nil {
				t.Fatalf("ParseVersion(%q) succeeded", value)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "0:1.0", 0},
		{"1.0", "1.0-0", 0},
		{"1.0-0", "1.0-00", 0},
		{"1.001", "1.1", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~~", "1.0~", -1},
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0-1ubuntu1", -1},
		{"1.0-1ubuntu1", "1.0-1ubuntu2", -1},
		{"1.0a", "1.0", 1},
		{"1.0a", "1.0+", -1},
		{"1.0+", "1.0", 1},
		{"1:0.1", "2.0", 1},
		{"2.0", "1:0.1", -1},
		{"1.0-1", "1.0-1~", 1},
		{"1.0-1~", "1.0-1", -1},
		{"1.0-1+b1", "1.0-1", 1},
		{"1.0.0", "1.0", 1},
		{"1.0-1.1", "1.0-1", 1},
		{"9.0", "10.0", -1},
		{"1.0-10", "1.0-9", 1},
		{"0.9", "1.0", -1},
	}
	for _, test := range tests {
		t.Run(test.a+"_"+test.b, func(t *testing.T) {
			a, err := deb.ParseVersion(test.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := deb.ParseVersion(test.b)
			if err != nil {
				t.Fatal(err)
			}
			if got := a.Compare(b); got != test.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", test.a, test.b, got, test.want)
			}
			if got := b.Compare(a); got != -test.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", test.b, test.a, got, -test.want)
			}
		})
	}
}

func TestCompareVersionOrder(t *testing.T) {
	order := []string{
		"0",
		"0.9",
		"1.0~~",
		"1.0~rc1",
		"1.0~rc2",
		"1.0",
		"1.0-1~",
		"1.0-1",
		"1.0-1ubuntu1",
		"1.0-1ubuntu2",
		"1.0a",
		"1.0+",
		"1.0.0",
		"2.0",
		"1:0.1",
	}
	parsed := make([]deb.Version, len(order))
	for i, value := range order {
		version, err := deb.ParseVersion(value)
		if err != nil {
			t.Fatal(err)
		}
		parsed[i] = version
	}
	for i := range parsed {
		for j := range parsed {
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got := parsed[i].Compare(parsed[j]); got != want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
}

func TestVersionStringRoundTrips(t *testing.T) {
	for _, value := range []string{"0", "1.0", "1.0-0", "1:2.0-3", "2.0~rc1+deb12u1"} {
		version, err := deb.ParseVersion(value)
		if err != nil {
			t.Fatal(err)
		}
		if got := version.String(); got != value {
			t.Fatalf("String() = %q, want %q", got, value)
		}
	}
	if got := (deb.Version{Upstream: "1.0"}).String(); got != "1.0" {
		t.Fatalf("zero epoch String() = %q", got)
	}
}
