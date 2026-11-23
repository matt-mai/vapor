package deb

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

func readPackageStanzas(data []byte) ([]map[string]string, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("package index is malformed")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), MaxPackageLineSize)
	var stanzas []map[string]string
	var err error
	stanza := newPackageStanza()
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			stanzas, err = appendStanza(stanzas, stanza)
			if err != nil {
				return nil, err
			}
			stanza = newPackageStanza()
			continue
		}
		if err := stanza.readLine(line); err != nil {
			return nil, err
		}
	}
	if err := packageScannerError(scanner); err != nil {
		return nil, err
	}
	return appendStanza(stanzas, stanza)
}

func packageScannerError(scanner *bufio.Scanner) error {
	err := scanner.Err()
	if err == nil {
		return nil
	}
	if errors.Is(err, bufio.ErrTooLong) {
		return fmt.Errorf("package index line exceeds %d bytes", MaxPackageLineSize)
	}
	return errors.New("package index is malformed")
}

func appendStanza(stanzas []map[string]string, stanza *packageStanza) ([]map[string]string, error) {
	if err := stanza.finish(); err != nil {
		return nil, err
	}
	if stanza.hasFields() {
		stanzas = append(stanzas, stanza.fields)
	}
	return stanzas, nil
}

type packageStanza struct {
	fields   map[string]string
	seen     map[string]struct{}
	current  string
	retained bool
	value    strings.Builder
	size     int
}

func newPackageStanza() *packageStanza {
	return &packageStanza{
		fields: make(map[string]string),
		seen:   make(map[string]struct{}),
	}
}

func (s *packageStanza) hasFields() bool {
	return len(s.seen) > 0
}

func (s *packageStanza) readLine(line string) error {
	if line[0] == ' ' || line[0] == '\t' {
		if s.current == "" {
			return errors.New("package index is malformed")
		}
		if !s.retained {
			return nil
		}
		return s.appendValue(strings.TrimSpace(line))
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok || !validFieldName(name) {
		return errors.New("package index is malformed")
	}
	name = strings.ToLower(name)
	if _, duplicate := s.seen[name]; duplicate {
		return errors.New("package index is malformed")
	}
	if len(s.seen) >= MaxPackageFields {
		return fmt.Errorf("package index stanza exceeds %d fields", MaxPackageFields)
	}
	if err := s.finish(); err != nil {
		return err
	}
	s.seen[name] = struct{}{}
	s.current = name
	s.retained = retainedPackageField(name)
	if s.retained {
		return s.appendValue(strings.TrimSpace(value))
	}
	return nil
}

func (s *packageStanza) appendValue(value string) error {
	if value == "" {
		return nil
	}
	size := s.value.Len() + len(value)
	if s.value.Len() > 0 {
		size++
	}
	if size > MaxPackageFieldSize {
		return fmt.Errorf("package index field exceeds %d bytes", MaxPackageFieldSize)
	}
	if s.value.Len() > 0 {
		s.value.WriteByte(' ')
	}
	s.value.WriteString(value)
	return nil
}

func (s *packageStanza) finish() error {
	if s.current == "" {
		return nil
	}
	if s.retained {
		if s.size+s.value.Len() > MaxPackageStanzaSize {
			return fmt.Errorf("package index stanza exceeds %d bytes", MaxPackageStanzaSize)
		}
		s.size += s.value.Len()
		s.fields[s.current] = s.value.String()
	}
	s.current = ""
	s.retained = false
	s.value.Reset()
	return nil
}

func retainedPackageField(name string) bool {
	switch name {
	case "package", "source", "version", "architecture", "multi-arch", "filename", "size", "sha256",
		"pre-depends", "depends", "provides", "conflicts", "breaks", "replaces":
		return true
	}
	return false
}
