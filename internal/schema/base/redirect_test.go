package base_test

import (
	"testing"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// A query is the signature a server puts on its own asset URL, so the target that
// carries one has to be HTTPS: plaintext publishes the signature itself, and the
// digest check afterwards only protects the bytes it was attached to.
func TestValidateRedirectURL_AllowsAQueryOnlyOverTLS(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"https://release-assets.example.com/asset?sp=r&sig=abc",
		"https://example.com/asset",
		"http://example.com/asset",
	} {
		if err := base.ValidateRedirectURL(value); err != nil {
			t.Fatalf("valid redirect target refused: %v", err)
		}
	}
	for _, value := range []string{
		"http://example.com/asset?sig=abc",
		"http://example.com/asset?",
		"ftp://example.com/asset",
		"https://user:pass@example.com/asset",
		"https://example.com/asset#fragment",
	} {
		if err := base.ValidateRedirectURL(value); err == nil {
			t.Fatalf("invalid redirect target accepted: %q", value)
		}
	}
}
