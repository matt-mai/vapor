package ui

import (
	"fmt"
)

// HumanBytes renders a byte count in the largest binary unit that keeps it readable.
// Architects read MiB as 1024-based and GB as decimal, so a build report says MiB
// explicitly rather than leaving the reader to guess which one a bare number meant.
func HumanBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value, suffix := float64(size), ""
	for _, next := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= unit
		suffix = next
		if value < unit {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", value, suffix)
}
