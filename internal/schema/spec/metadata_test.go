package spec

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestLoadSpec_Metadata(t *testing.T) {
	t.Parallel()
	tags := []string{"z", "v2", "V2", "_build", "latest", "42", strings.Repeat("a", 128)}
	annotations := map[string]string{
		"org.opencontainers.image.description": "first\nsecond\n",
		"custom":                               "", "custom/Unicode": "café",
	}
	input := minimalSpec + "tags: [" + strings.Join(tags[:5], ", ") + ", '42', " + tags[6] + "]\n" +
		"annotations:\n  org.opencontainers.image.description: |\n    first\n    second\n" +
		"  custom: ''\n  custom/Unicode: café\n"
	spec, err := loadText(t, input)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(spec.Tags, tags) || !maps.Equal(spec.Annotations, annotations) {
		t.Fatalf("metadata changed: tags=%#v annotations=%#v", spec.Tags, spec.Annotations)
	}
}

func TestLoadSpec_MetadataOmissionAndEmpty(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"", "tags: []\nannotations: {}\n"} {
		spec, err := loadText(t, minimalSpec+suffix)
		if err != nil {
			t.Fatal(err)
		}
		if len(spec.Tags) != 0 || len(spec.Annotations) != 0 {
			t.Fatal("unexpected default metadata")
		}
		if (spec.Tags == nil) != (suffix == "") || (spec.Annotations == nil) != (suffix == "") {
			t.Fatal("omission/empty representation changed")
		}
	}
}

func TestLoadSpec_InvalidTags(t *testing.T) {
	t.Parallel()
	for i, tag := range []string{"", ".start", "-start", strings.Repeat("a", 129), "café", "a b", "a/b", "a:b", "a@b", "a\nb"} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+"tags: ["+strconv.Quote(tag)+"]")
			if err == nil || spec != nil || !strings.Contains(err.Error(), "tags[0]") {
				t.Fatalf("want invalid tag error, got spec=%#v err=%v", spec, err)
			}
		})
	}
	spec, err := loadText(t, minimalSpec+"tags: [v1, v1]")
	if err == nil || spec != nil || !strings.Contains(err.Error(), "duplicate image tag") {
		t.Fatalf("duplicate tag: spec=%#v err=%v", spec, err)
	}
}

func TestLoadSpec_MetadataStrictYAML(t *testing.T) {
	t.Parallel()
	for i, suffix := range []string{
		"tags: v1", "tags: {}", "tags: null", "tags: [null]", "tags: [42]", "tags: [true]",
		"tags: ['${TAG}']", "tags: [\"a\\0b\"]", "tags: &tags [v1]", "tags: [!custom v1]",
		"annotations: []", "annotations: text", "annotations: null", "annotations: {1: text}",
		"annotations: {custom: null}", "annotations: {custom: 42}", "annotations: {custom: true}",
		"annotations: {custom: {nested: text}}", "annotations: {custom: [text]}",
		"annotations: {custom: one, custom: two}", "annotations: {'': text}", "annotations: {'   ': text}",
		"annotations: {'${KEY}': text}", "annotations: {custom: '${VALUE}'}",
		"annotations: {\"bad\\0key\": text}", "annotations: {custom: \"a\\0b\"}",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+suffix)
			if err == nil || spec != nil {
				t.Fatalf("want rejection, got spec=%#v err=%v", spec, err)
			}
		})
	}
}

func TestLoadSpec_MetadataErrorsAreRedacted(t *testing.T) {
	t.Parallel()
	const secret = "sensitive-marker"
	for i, suffix := range []string{
		"tags: ['." + secret + "']",
		"tags: [" + secret + ", " + secret + "]",
		"annotations: {" + secret + ": [" + secret + "]}",
		"annotations: {" + secret + ": one, " + secret + ": two}",
		"annotations: {\"" + secret + "\\0\": text}",
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+suffix)
			if err == nil || spec != nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("want redacted metadata failure, got spec=%#v err=%v", spec, err)
			}
		})
	}
}
