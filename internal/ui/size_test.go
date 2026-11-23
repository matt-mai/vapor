package ui

import "testing"

// TestHumanBytesUsesBinaryUnits pins the unit a build report prints. A bare number
// would leave the reader guessing whether 12991583 was decimal or binary GB.
func TestHumanBytesUsesBinaryUnits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{12991583, "12.4 MiB"},
		{1536 << 10, "1.5 MiB"},
		{3 << 30, "3.0 GiB"},
	} {
		if got := HumanBytes(tc.bytes); got != tc.want {
			t.Fatalf("HumanBytes(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}
