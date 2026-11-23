package spec

import (
	"strconv"
	"strings"
	"testing"
)

func TestLoadSpec_AbsoluteLocalInputsRejected(t *testing.T) {
	t.Parallel()
	for i, input := range []string{
		minimalSpec + "contents: {catalogues: [{name: local, path: /host/catalogue}]}",
		strings.Replace(contentsFixture, "keys/repo.asc", "/host/repo.asc", 1),
		minimalSpec + "filesystem: {ca: {mode: append, sources: [/host/ca.pem]}}",
		minimalSpec + "vex: {inputs: [/host/vex.json]}",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, input)
			if spec != nil || err == nil || !strings.Contains(err.Error(), "relative") || strings.Contains(err.Error(), "/host/") {
				t.Fatalf("want redacted relative-path rejection: %v", err)
			}
		})
	}
}
