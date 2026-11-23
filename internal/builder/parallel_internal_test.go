package builder

import (
	"context"
	"math"
	"testing"

	"github.com/matt-mai/vapor/internal/oci"
)

func (i *Input) ParallelErrorsForTest(ctx context.Context, platforms []oci.Platform) ([]error, error) {
	built, err := i.buildConcurrently(ctx, platforms, oci.DefaultCompression, 2, func(oci.Platform) error { return nil })
	failures := make([]error, len(built))
	for index := range built {
		failures[index] = built[index].err
	}
	return failures, err
}

func TestBuildWorkerCount(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		jobs, platforms, want int
	}{
		{name: "serial", jobs: 1, platforms: 2, want: 1},
		{name: "below one", jobs: 0, platforms: 2, want: 1},
		{name: "at platform count", jobs: 2, platforms: 2, want: 2},
		{name: "above platform count", jobs: math.MaxInt, platforms: 2, want: 2},
		{name: "no platforms", jobs: 1, platforms: 0, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildWorkerCount(tc.jobs, tc.platforms); got != tc.want {
				t.Fatalf("worker count = %d, want %d", got, tc.want)
			}
		})
	}
}
