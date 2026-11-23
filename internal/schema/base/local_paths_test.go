package base_test

import (
	"strconv"
	"testing"

	"github.com/matt-mai/vapor/internal/schema/base"
)

func TestValidateLocalPath_PortableRelativeIdentity(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"keys/root.asc", "../shared/key.asc", ".", "a b/root.pem"} {
		if err := base.ValidateLocalPath(value); err != nil {
			t.Fatalf("valid relative declaration rejected: %v", err)
		}
	}
	for i, value := range []string{"", "/etc/key.asc", `C:/keys/root.asc`, `C:root.asc`, `keys\root.asc`, `\\host\key`, "./root.asc", "a/../root.asc", "a//root.asc", "a/", " root.asc", "root.asc ", "a\nb", "a\x00b"} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if err := base.ValidateLocalPath(value); err == nil {
				t.Fatal("invalid local declaration accepted")
			}
		})
	}
}
