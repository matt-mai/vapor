package builder_test

import (
	"context"
	"sync"
	"testing"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/oci"
)

// Assembly is the longest step of a build, so it has to say what it is doing while it
// does it. Every archive it unpacks is named, and the measurement it carries reaches
// the locked bytes exactly when the last one starts.
func TestBuild_ReportsWhatAssemblyUnpacks(t *testing.T) {
	inputs, _ := parallelFixture(t)
	var mu sync.Mutex
	var steps []builder.Step
	inputs.Progress = func(step builder.Step) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, step)
	}
	input, err := builder.Open(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.BuildEach(context.Background(), oci.DefaultCompression, 2, func(oci.Platform) error { return nil }); err != nil {
		t.Fatalf("BuildEach: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	named := make(map[string]bool, len(steps))
	var done, total int64
	for _, step := range steps {
		named[step.Name] = true
		done, total = max(done, step.Done), max(total, step.Total)
	}
	if !named["amd64"] || !named["arm64"] {
		t.Fatalf("assembly did not name both artifacts: %v", steps)
	}
	if !named["compress layer"] {
		t.Fatalf("assembly did not name the compression stage: %v", steps)
	}
	if total == 0 || done != total {
		t.Fatalf("measurement reached %d of %d bytes, want the locked total", done, total)
	}
}
