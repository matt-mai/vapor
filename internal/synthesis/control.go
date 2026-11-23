package synthesis

import (
	"fmt"
	"strings"
)

// controlField is one control field with its value kept verbatim, continuation
// lines included, so the database never reformats a description.
type controlField struct {
	name  string
	value string
}

// parseControlStanza splits a control member into fields, keeping continuation
// lines attached to the field they belong to.
func parseControlStanza(name string, data []byte) ([]controlField, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("package %q has no control stanza", name)
	}
	if len(data) > MaxControlStanzaSize {
		return nil, fmt.Errorf("package %q control stanza exceeds %d bytes", name, MaxControlStanzaSize)
	}
	stanza := &controlStanzaReader{name: name, seen: make(map[string]struct{})}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		if err := stanza.readLine(line); err != nil {
			return nil, err
		}
	}
	if len(stanza.fields) == 0 {
		return nil, fmt.Errorf("package %q has no control stanza", name)
	}
	return stanza.fields, nil
}

// controlStanzaReader accumulates fields so continuation handling stays out of
// the loop that splits lines.
type controlStanzaReader struct {
	name   string
	fields []controlField
	seen   map[string]struct{}
}

func (s *controlStanzaReader) readLine(line string) error {
	if line[0] == ' ' || line[0] == '\t' {
		if len(s.fields) == 0 {
			return malformedControl(s.name)
		}
		s.fields[len(s.fields)-1].value += "\n" + line
		return nil
	}
	field, value, ok := strings.Cut(line, ":")
	if !ok || !validControlFieldName(field) {
		return malformedControl(s.name)
	}
	if _, duplicate := s.seen[field]; duplicate {
		return malformedControl(s.name)
	}
	s.seen[field] = struct{}{}
	s.fields = append(s.fields, controlField{name: field, value: strings.TrimSpace(value)})
	return nil
}

func malformedControl(name string) error {
	return fmt.Errorf("package %q control stanza is malformed", name)
}

func validControlFieldName(name string) bool {
	if name == "" || !isControlNameByte(name[0], true) {
		return false
	}
	for index := 1; index < len(name); index++ {
		if !isControlNameByte(name[index], false) {
			return false
		}
	}
	return true
}

func isControlNameByte(value byte, first bool) bool {
	switch {
	case value >= 'A' && value <= 'Z', value >= 'a' && value <= 'z':
		return true
	case value >= '0' && value <= '9':
		return !first
	case value == '-':
		return !first
	}
	return false
}

// checkControlIdentity rejects a stanza that describes another package, which
// would otherwise record a version the image does not contain.
func checkControlIdentity(pkg *PackageState, fields []controlField) error {
	declared := map[string]string{
		fieldPackage:      pkg.Name,
		fieldVersion:      pkg.Version,
		fieldArchitecture: pkg.Architecture,
	}
	for _, field := range fields {
		want, known := declared[field.name]
		if !known {
			continue
		}
		if field.value != want {
			return fmt.Errorf("package %q control stanza declares %s %q, not %q",
				pkg.Name, field.name, field.value, want)
		}
	}
	return nil
}
