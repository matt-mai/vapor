package builder

import (
	"fmt"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/vfs"
)

// The import limits bound one archive. An image assembled from many archives needs
// a bound of its own, or its peak memory is the sum of everything it admitted.
func TestBudget_BoundsTheImageNotTheArchive(t *testing.T) {
	// The budget is scaled down rather than filled to the real bound: charging a
	// tree of a million entries would make this test a memory benchmark.
	budgeted := &extractionBudget{entries: 8, bytes: imageBudget().bytes}
	half := vfs.New()
	for index := range 5 {
		if err := half.File(fmt.Sprintf("/f%d", index), nil, vfs.Attrs{Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := budgeted.charge(half); err != nil {
		t.Fatalf("first half: %v", err)
	}
	if err := budgeted.charge(half); err == nil ||
		!strings.Contains(err.Error(), "image content exceeds") {
		t.Fatalf("second half error = %v, want the image bound enforced", err)
	}
}

// Content bytes are bounded the same way, so many small packages that each fit
// cannot add up to an image that does not.
func TestBudget_BoundsBytes(t *testing.T) {
	budget := imageBudget()
	budgeted := &extractionBudget{entries: budget.entries, bytes: 16}
	large := vfs.New()
	if err := large.File("/a", make([]byte, 9), vfs.Attrs{Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := budgeted.charge(large); err != nil {
		t.Fatalf("first package: %v", err)
	}
	if err := budgeted.charge(large); err == nil ||
		!strings.Contains(err.Error(), "image content exceeds") {
		t.Fatalf("second package error = %v, want the image bound enforced", err)
	}
}
