package slices_test

import (
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/distro/slices"
)

func TestParseCatalogue_Maintenance(t *testing.T) {
	key := testRootKey(t)
	base := catalogueYAML(key.id, key.armor)
	t.Run("incomplete", func(t *testing.T) {
		data := replace(t, base, "  end-of-life: 2038-04-27\n", "")
		if _, err := slices.ParseCatalogue([]byte(data)); err == nil || !strings.Contains(err.Error(), "end-of-life") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("invalid date", func(t *testing.T) {
		_, err := slices.ParseCatalogue([]byte(replace(t, base, "2026-04-23", "23-04-2026")))
		if err == nil || !strings.Contains(err.Error(), "YYYY-MM-DD") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("defaults", func(t *testing.T) {
		data := replace(t, base, "maintenance:\n  standard: 2026-04-23\n  end-of-life: 2038-04-27\n", "maintenance: {}\n")
		catalogue := parseRoot(t, data)
		if got := catalogue.Maintenance.Standard.Format(time.DateOnly); got != "2026-04-23" {
			t.Fatalf("standard = %q", got)
		}
		if got := catalogue.Maintenance.Legacy.Format(time.DateOnly); got != "2036-04-23" {
			t.Fatalf("legacy = %q", got)
		}
	})
	t.Run("unknown default", func(t *testing.T) {
		data := replace(t, base, "maintenance:\n  standard: 2026-04-23\n  end-of-life: 2038-04-27\n", "maintenance: {}\n")
		data = replace(t, data, "version: \"26.04\"", "version: \"99.04\"")
		if _, err := slices.ParseCatalogue([]byte(data)); err == nil || !strings.Contains(err.Error(), "standard") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestMaintenance_Warnings(t *testing.T) {
	t.Parallel()
	maintenance := slices.Maintenance{
		Standard:  time.Date(2026, time.April, 23, 0, 0, 0, 0, time.UTC),
		Expanded:  time.Date(2031, time.May, 29, 0, 0, 0, 0, time.UTC),
		EndOfLife: time.Date(2038, time.April, 27, 0, 0, 0, 0, time.UTC),
	}
	cases := []struct {
		name string
		now  time.Time
		want string
	}{
		{"before the release date", maintenance.Standard.AddDate(-1, 0, 0), ""},
		{"on the release date", maintenance.Standard, ""},
		{"during standard support", maintenance.Expanded.AddDate(-1, 0, 0), ""},
		{"on the expanded date", maintenance.Expanded, ""},
		{"after standard support ends", maintenance.Expanded.AddDate(0, 0, 1), "standard support"},
		{"after end-of-life", maintenance.EndOfLife.AddDate(0, 0, 1), "end-of-life"},
		{"no expanded date before end-of-life", maintenance.EndOfLife.AddDate(-1, 0, 0), ""},
		{"dates unset", time.Date(2038, time.April, 27, 0, 0, 0, 0, time.UTC), ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			subject := maintenance
			if testCase.name == "dates unset" {
				subject = slices.Maintenance{}
			}
			if testCase.name == "no expanded date before end-of-life" {
				subject.Expanded = time.Time{}
			}
			warnings := subject.Warnings(testCase.now)
			if testCase.want == "" {
				if len(warnings) != 0 {
					t.Fatalf("warnings = %q, want none", warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], testCase.want) {
				t.Fatalf("warnings = %q, want one mentioning %q", warnings, testCase.want)
			}
		})
	}
}
