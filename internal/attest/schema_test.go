package attest_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/matt-mai/vapor/internal/attest"
)

// TestSPDX_ValidatesAgainstSchema checks the payload against the published SPDX 2.3.1
// schema, so a field the schema does not allow is a test failure rather than a
// surprise for the consumer.
func TestSPDX_ValidatesAgainstSchema(t *testing.T) {
	schema := loadSchema(t)
	input, _ := newSBOMFixture()
	payload, err := attest.SPDX(input)
	if err != nil {
		t.Fatalf("SPDX: %v", err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	if err := validateSchema(schema, document, "document"); err != nil {
		t.Fatalf("payload does not satisfy the SPDX schema: %v", err)
	}
}

// validatedKeywords are the assertions the offline validator below implements. The
// published SPDX schema uses only these, which TestSchemaValidator_CoversSchema checks,
// so an unimplemented keyword cannot silently pass.
var validatedKeywords = map[string]bool{
	"$schema": true, "$id": true, "title": true, "$comment": true, "description": true,
	"deprecated": true, "type": true, "properties": true, "items": true, "required": true,
	"additionalProperties": true, "pattern": true, "enum": true, "minItems": true,
}

// validateSchema checks value against a schema decoded into map[string]any and returns
// a path-qualified error for the first violation.
func validateSchema(schema map[string]any, value any, path string) error {
	if wanted, ok := schema["type"].(string); ok && !matchesType(wanted, value) {
		return fmt.Errorf("%s: want %s, got %T", path, wanted, value)
	}
	if allowed, ok := schema["enum"].([]any); ok && !matchesEnum(allowed, value) {
		return fmt.Errorf("%s: %v is not one of %v", path, value, allowed)
	}
	if pattern, ok := schema["pattern"].(string); ok {
		text, isText := value.(string)
		if !isText {
			return fmt.Errorf("%s: pattern applies to a string", path)
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("%s: bad schema pattern: %w", path, err)
		}
		if !compiled.MatchString(text) {
			return fmt.Errorf("%s: %q does not match %s", path, text, pattern)
		}
	}
	switch typed := value.(type) {
	case map[string]any:
		return validateObject(schema, typed, path)
	case []any:
		return validateArray(schema, typed, path)
	}
	return nil
}

func validateObject(schema, value map[string]any, path string) error {
	if wanted, ok := schema["required"].([]any); ok {
		for _, name := range wanted {
			if _, present := value[name.(string)]; !present {
				return fmt.Errorf("%s: missing %s", path, name)
			}
		}
	}
	properties, _ := schema["properties"].(map[string]any)
	for _, name := range sortedKeys(value) {
		child, known := properties[name]
		if !known {
			if allowed, declared := schema["additionalProperties"].(bool); declared && !allowed {
				return fmt.Errorf("%s: unexpected property %s", path, name)
			}
			continue
		}
		nested, ok := child.(map[string]any)
		if !ok {
			continue
		}
		if err := validateSchema(nested, value[name], path+"."+name); err != nil {
			return err
		}
	}
	return nil
}

func validateArray(schema map[string]any, value []any, path string) error {
	if wanted, ok := schema["minItems"].(float64); ok && float64(len(value)) < wanted {
		return fmt.Errorf("%s: %d items, want at least %v", path, len(value), wanted)
	}
	items, ok := schema["items"].(map[string]any)
	if !ok {
		return nil
	}
	for index, item := range value {
		if err := validateSchema(items, item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func matchesType(wanted string, value any) bool {
	switch wanted {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number", "integer":
		_, ok := value.(float64)
		return ok
	case "null":
		return value == nil
	}
	return false
}

func matchesEnum(allowed []any, value any) bool {
	for _, candidate := range allowed {
		if fmt.Sprint(candidate) == fmt.Sprint(value) {
			return true
		}
	}
	return false
}

func sortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for name := range value {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}

// TestSchemaValidator_CoversSchema checks that the published schema uses only the
// keywords the validator implements, so validation is not weaker than it looks.
func TestSchemaValidator_CoversSchema(t *testing.T) {
	var document any
	data := readSchemaBytes(t)
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	unknown := map[string]bool{}
	walkSchema(document, func(node map[string]any) {
		for name := range node {
			if !validatedKeywords[name] {
				unknown[name] = true
			}
		}
	})
	if len(unknown) != 0 {
		names := make([]string, 0, len(unknown))
		for name := range unknown {
			names = append(names, name)
		}
		sort.Strings(names)
		t.Fatalf("validator does not implement %v", names)
	}
}

// TestSchemaValidator_RejectsBrokenPayloads checks that the validator actually fails on
// the mistakes a generator makes: a wrong type, a missing required field and an
// unexpected property.
func TestSchemaValidator_RejectsBrokenPayloads(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(readSchemaBytes(t), &schema); err != nil {
		t.Fatal(err)
	}
	if err := validateSchema(schema, validDocument(), "document"); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	cases := map[string]func(map[string]any){
		"missing license": func(document map[string]any) { delete(document, "dataLicense") },
		"bad creators": func(document map[string]any) {
			document["creationInfo"].(map[string]any)["creators"] = []any{}
		},
		"bad timestamp": func(document map[string]any) {
			document["creationInfo"].(map[string]any)["created"] = "yesterday"
		},
		"unknown package property": func(document map[string]any) {
			packageOf(document)["downloadLocation"] = "NOASSERTION"
			packageOf(document)["licenseListVersion"] = "3.22"
		},
		"wrong type": func(document map[string]any) { document["packages"] = map[string]any{} },
		"package field": func(document map[string]any) {
			packageOf(document)["filesAnalyzed"] = "true"
		},
		"empty checksum": func(document map[string]any) {
			packageOf(document)["checksums"] = []any{map[string]any{
				"algorithm": "SHA256", "checksumValue": "",
			}}
		},
	}
	for name, breakIt := range cases {
		document := validDocument()
		breakIt(document)
		if err := validateSchema(schema, document, "document"); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// validDocument is a minimal payload the published schema accepts, rebuilt per case so
// one broken case cannot leak into the next.
func validDocument() map[string]any {
	return map[string]any{
		"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0", "name": "image", "documentNamespace": "https://example.invalid/x",
		"creationInfo": map[string]any{
			"created":  "1970-01-01T00:00:00Z",
			"creators": []any{"Tool: vaporize"},
		},
		"packages": []any{map[string]any{
			"SPDXID": "SPDXRef-Package-a", "name": "a", "downloadLocation": "NOASSERTION",
			"filesAnalyzed": true,
		}},
	}
}

func packageOf(document map[string]any) map[string]any {
	return document["packages"].([]any)[0].(map[string]any)
}

func readSchemaBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/spdx-2.3.1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// walkSchema visits every subschema node, which are objects that describe a type or
// hold properties.
func walkSchema(value any, visit func(map[string]any)) {
	node, ok := value.(map[string]any)
	if !ok {
		if list, isList := value.([]any); isList {
			for _, item := range list {
				walkSchema(item, visit)
			}
		}
		return
	}
	if _, describes := node["type"]; describes {
		visit(node)
	}
	for _, child := range node {
		switch typed := child.(type) {
		case map[string]any:
			if _, describes := typed["type"]; describes {
				walkSchema(typed, visit)
				continue
			}
			for _, nested := range typed {
				walkSchema(nested, visit)
			}
		case []any:
			walkSchema(typed, visit)
		}
	}
}
