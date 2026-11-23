package slices

import (
	"fmt"
	"time"
)

// ubuntuArchive is the only archive with built-in lifecycle dates. Every other
// distribution's catalogue has to state them.
const ubuntuArchive = "ubuntu"

var defaultMaintenance = map[string]Maintenance{
	"20.04": dates(2020, time.April, 23, 2025, time.May, 29, 2030, time.April, 23, 2032, time.April, 27),
	"22.04": dates(2022, time.April, 21, 2027, time.June, 1, 2032, time.April, 21, 2034, time.April, 25),
	"22.10": dates(2022, time.October, 20, 0, 0, 0, 0, 0, 0, 2023, time.July, 20),
	"23.04": dates(2023, time.April, 20, 0, 0, 0, 0, 0, 0, 2024, time.January, 25),
	"23.10": dates(2023, time.October, 12, 0, 0, 0, 0, 0, 0, 2024, time.July, 11),
	"24.04": dates(2024, time.April, 25, 2029, time.May, 31, 2034, time.April, 25, 2036, time.April, 29),
	"24.10": dates(2024, time.October, 10, 0, 0, 0, 0, 0, 0, 2025, time.July, 10),
	"25.04": dates(2025, time.April, 17, 0, 0, 0, 0, 0, 0, 2026, time.January, 15),
	"25.10": dates(2025, time.October, 9, 0, 0, 0, 0, 0, 0, 2026, time.July, 9),
	"26.04": dates(2026, time.April, 23, 2031, time.May, 29, 2036, time.April, 23, 2038, time.April, 27),
}

// Maintenance records the catalogue lifecycle dates.
type Maintenance struct {
	Standard  time.Time
	Expanded  time.Time
	Legacy    time.Time
	EndOfLife time.Time
}

type rawMaintenance struct {
	Standard  string `yaml:"standard"`
	Expanded  string `yaml:"expanded"`
	Legacy    string `yaml:"legacy"`
	EndOfLife string `yaml:"end-of-life"`
}

func parseMaintenance(raw rawMaintenance, archives map[string]Archive) (Maintenance, error) {
	if raw == (rawMaintenance{}) {
		if archive, ok := archives[ubuntuArchive]; ok {
			if maintenance, ok := defaultMaintenance[archive.Version]; ok {
				return maintenance, nil
			}
		}
	}
	return parseMaintenanceDates(raw)
}

func parseMaintenanceDates(raw rawMaintenance) (Maintenance, error) {
	var maintenance Maintenance
	for _, field := range []struct {
		name  string
		value string
		date  *time.Time
	}{
		{"standard", raw.Standard, &maintenance.Standard},
		{"end-of-life", raw.EndOfLife, &maintenance.EndOfLife},
		{"expanded", raw.Expanded, &maintenance.Expanded},
		{"legacy", raw.Legacy, &maintenance.Legacy},
	} {
		if field.value == "" {
			if field.name == "standard" || field.name == "end-of-life" {
				return Maintenance{}, fmt.Errorf("catalogue maintenance %q is unset", field.name)
			}
			continue
		}
		date, err := time.Parse(time.DateOnly, field.value)
		if err != nil {
			return Maintenance{}, fmt.Errorf("catalogue maintenance %q must be YYYY-MM-DD", field.name)
		}
		*field.date = date
	}
	return maintenance, nil
}

// Warnings reports maintenance state that is over by now. A catalogue does not become
// wrong when a date passes, so this never fails a lock; the dates are metadata about
// support, not about the bytes. End-of-life is reported instead of the earlier standard
// date it supersedes.
func (m *Maintenance) Warnings(now time.Time) []string {
	switch {
	case past(now, m.EndOfLife):
		return []string{fmt.Sprintf("catalogue is past its end-of-life date %s",
			m.EndOfLife.Format(time.DateOnly))}
	case past(now, m.Standard):
		return []string{fmt.Sprintf("catalogue is past its standard support date %s",
			m.Standard.Format(time.DateOnly))}
	}
	return nil
}

func past(now, date time.Time) bool { return !date.IsZero() && now.After(date) }

func dates(
	standardYear int,
	standardMonth time.Month,
	standardDay, expandedYear int,
	expandedMonth time.Month,
	expandedDay, legacyYear int,
	legacyMonth time.Month,
	legacyDay, endYear int,
	endMonth time.Month,
	endDay int,
) Maintenance {
	maintenance := Maintenance{
		Standard:  time.Date(standardYear, standardMonth, standardDay, 0, 0, 0, 0, time.UTC),
		EndOfLife: time.Date(endYear, endMonth, endDay, 0, 0, 0, 0, time.UTC),
	}
	if expandedYear != 0 {
		maintenance.Expanded = time.Date(expandedYear, expandedMonth, expandedDay, 0, 0, 0, 0, time.UTC)
	}
	if legacyYear != 0 {
		maintenance.Legacy = time.Date(legacyYear, legacyMonth, legacyDay, 0, 0, 0, 0, time.UTC)
	}
	return maintenance
}
