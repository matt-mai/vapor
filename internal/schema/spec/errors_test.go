package spec

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadSpec_MalformedValuesAreRedacted(t *testing.T) {
	t.Parallel()
	const secret = "sensitive_marker_7f2b"
	for i, suffix := range []string{
		"container: {env: " + secret + "}",
		"container: {env: [" + secret + "]}",
		"container: {env: {TOKEN: [" + secret + "]}}",
		"container: {env: {TOKEN: {nested: " + secret + "}}}",
		"container: {env: {TOKEN: *" + secret + "}}",
		"container: {env: {TOKEN:" + secret + "}}",
		"container: {env: {" + secret + ": value, " + secret + ": other}}",
		"container: {env: {'TOKEN:" + secret + "': value}}",
		"---\ncontainer: {env: {TOKEN: *" + secret + "}}",
		"container: " + secret,
		"container: {ports: [" + secret + "]}",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+suffix)
			if err == nil || spec != nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("malformed input must fail without echoing values: spec=%#v err=%v", spec, err)
			}
		})
	}
	input := strings.Replace(minimalSpec, "ghcr.io/example/ubuntu-minimal", "https://user:"+secret+"@registry.example/app", 1)
	if spec, err := loadText(t, input); err == nil || spec != nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("image credentials were accepted or exposed: spec=%#v err=%v", spec, err)
	}
}

func TestLoadSpec_YAMLCauseRetainedWithoutValue(t *testing.T) {
	t.Parallel()
	oversized := "18446744073709551615"
	input := strings.Replace(minimalSpec, "version: 1", "version: "+oversized, 1)
	spec, err := loadText(t, input)
	var cause *yaml.TypeError
	if err == nil || spec != nil || !errors.As(err, &cause) || strings.Contains(err.Error(), oversized) {
		t.Fatalf("expected redacted error with YAML cause, got spec=%#v err=%v", spec, err)
	}
}
