package deb_test

import (
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestArchitecture(t *testing.T) {
	t.Parallel()
	tests := []struct {
		platform string
		want     string
		ok       bool
	}{
		{platform: "linux/amd64", want: "amd64", ok: true},
		{platform: "linux/arm64", want: "arm64", ok: true},
		{platform: "linux/386", ok: false},
		{platform: "all", ok: false},
		{platform: "", ok: false},
	}
	for _, test := range tests {
		got, ok := deb.Architecture(test.platform)
		if ok != test.ok || got != test.want {
			t.Errorf("Architecture(%q) = (%q, %t), want (%q, %t)", test.platform, got, ok, test.want, test.ok)
		}
	}
}
