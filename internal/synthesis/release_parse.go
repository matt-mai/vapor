package synthesis

import (
	"errors"
	"fmt"
	"strings"
)

func parseRelease(location string, content []byte) (map[string]string, error) {
	result := make(map[string]string)
	for line := range strings.Lines(string(content)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("%s has a malformed line %q", location, line)
		}
		if err := validateReleaseKey(key); err != nil {
			return nil, fmt.Errorf("%s has a malformed line %q: %w", location, line, err)
		}
		unquoted, err := unquoteRelease(value)
		if err != nil {
			return nil, fmt.Errorf("%s field %q: %w", location, key, err)
		}
		result[key] = unquoted
	}
	return result, nil
}

// validateReleaseKey requires a key that is a plain shell assignment name. The
// serializer writes the key unquoted, so a key is only safe if a shell reading the
// file would see an assignment and nothing else: `:; echo INJECTED; #` is data in
// the parser but a command in the output. Escaping the value cannot help, because
// the danger is in the key.
func validateReleaseKey(key string) error {
	if key == "" {
		return errors.New("field name is empty")
	}
	if strings.ContainsFunc(key, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_'
	}) {
		return errors.New("field name is not a plain identifier")
	}
	if key[0] >= '0' && key[0] <= '9' {
		return errors.New("field name starts with a digit")
	}
	return nil
}

// unquoteRelease removes the optional single or double quotes os-release allows.
// The two quoting styles are handled separately because they mean different things,
// as they do in a shell: a double-quoted value decodes escapes, while a
// single-quoted one is literal and keeps every backslash.
//
// Decoding double quotes is what makes parsing and serialization inverse: a value
// holding a backslash is written escaped, and reading it back unchanged is what
// stops the escaping from doubling on every pass. Nothing is evaluated — no
// variable, no command — because the value is data rather than a shell fragment.
func unquoteRelease(value string) (string, error) {
	if len(value) < 2 {
		return value, nil
	}
	first, last := value[0], value[len(value)-1]
	if first != last {
		return value, nil
	}
	switch first {
	case '"':
		return decodeRelease(value[1 : len(value)-1])
	case '\'':
		return literalRelease(value[1 : len(value)-1])
	default:
		return value, nil
	}
}

// decodeRelease expands the escape sequences the serializer emits inside double
// quotes. An unknown escape is refused rather than kept, so a value cannot smuggle
// syntax through. An apostrophe needs no escape there and is kept as written.
func decodeRelease(inner string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(inner))
	for index := 0; index < len(inner); index++ {
		character := inner[index]
		if character == '"' {
			return "", errors.New("value contains an unescaped quote")
		}
		if character != '\\' {
			builder.WriteByte(character)
			continue
		}
		escaped, next, err := decodeEscape(inner, index)
		if err != nil {
			return "", err
		}
		builder.WriteByte(escaped)
		index = next
	}
	return builder.String(), nil
}

// literalRelease returns a single-quoted value unchanged. A single quote cannot
// appear inside one, so it is the only character that ends the value.
func literalRelease(inner string) (string, error) {
	if strings.ContainsRune(inner, '\'') {
		return "", errors.New("value contains an unescaped quote")
	}
	return inner, nil
}

// decodeEscape expands the escape sequence starting at index, returning the byte it
// stands for and the index of its last character.
func decodeEscape(inner string, index int) (byte, int, error) {
	if index+1 == len(inner) {
		return 0, 0, errors.New("value ends with an incomplete escape")
	}
	switch escaped := inner[index+1]; escaped {
	case '\\', '"', '\'', '$', '`':
		return escaped, index + 1, nil
	default:
		return 0, 0, fmt.Errorf("value contains an unsupported escape %q", escaped)
	}
}
