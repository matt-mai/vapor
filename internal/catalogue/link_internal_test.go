package catalogue

import (
	"strings"
	"testing"
)

func TestLinkResolverStepLimit(t *testing.T) {
	resolver := &linkResolver{steps: maxLinkSteps}
	if _, err := resolver.walk(nil, "a", "link"); err == nil || !strings.Contains(err.Error(), "expansion limit") {
		t.Fatalf("error = %v", err)
	}
}
