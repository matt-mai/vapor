package synthesis

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/matt-mai/vapor/internal/vfs"
)

// the indexes that it is not an account: a blank line has an empty name and would
// otherwise collide with every other blank line.
type databaseRecord struct {
	name   string
	id     uint32
	fields []string
	raw    string
}

type database []databaseRecord

// byName indexes the records by name. A repeated name is refused rather than
// resolved: with two records for one account, a last-wins index and a first-match
// reader disagree, so a usable record could stay reachable behind a disabled one.
func (d database) byName(location string) (map[string]databaseRecord, error) {
	result := make(map[string]databaseRecord, len(d))
	for _, record := range d {
		if record.fields == nil {
			continue
		}
		if _, exists := result[record.name]; exists {
			return nil, fmt.Errorf("%s has more than one record for %q", location, record.name)
		}
		result[record.name] = record
	}
	return result, nil
}

// byID indexes the records by numeric id, refusing a repeated id for the same
// reason a repeated name is refused.
func (d database) byID(location string) (map[uint32]databaseRecord, error) {
	result := make(map[uint32]databaseRecord, len(d))
	for _, record := range d {
		if record.fields == nil {
			continue
		}
		if other, exists := result[record.id]; exists {
			return nil, fmt.Errorf("%s gives %q and %q the same id %d", location, other.name, record.name,
				record.id)
		}
		result[record.id] = record
	}
	return result, nil
}

// The account databases are read without a declaration asking for them, so the
// archive member limit does not apply: it bounds a package payload, not the work a
// parser does. A real passwd or group file is a few kilobytes, so a file beyond
// these bounds is either corrupt or hostile and is refused before it is read whole.
const (
	maxDatabaseBytes   = 1 << 20
	maxDatabaseRecords = 1 << 16
)

// readDatabase loads a colon-separated account database, preserving comments and
// blank lines so a selected package's file is not rewritten into a different
// shape. A missing file is an empty database.
func readDatabase(tree *vfs.Tree, file accountDatabaseFile) (database, error) {
	entry, ok := tree.Lookup(file.location)
	if !ok {
		return nil, nil
	}
	if entry.Size > maxDatabaseBytes {
		return nil, fmt.Errorf("%s is %d bytes, beyond the %d-byte account database bound",
			file.location, entry.Size, maxDatabaseBytes)
	}
	content, err := tree.Read(file.location)
	if err != nil {
		if errors.Is(err, vfs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return parseDatabase(file.location, content, file.idField)
}

// parseDatabase keeps comments and blank lines as raw records so rewriting a
// selected file does not reflow it. idIndex is the field holding the numeric id,
// or a negative value for a database that has none.
func parseDatabase(location string, content []byte, idIndex int) (database, error) {
	var result database
	for line := range strings.Lines(string(content)) {
		if len(result) == maxDatabaseRecords {
			return nil, fmt.Errorf("%s has more than %d records", location, maxDatabaseRecords)
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" || strings.HasPrefix(line, "#") {
			result = append(result, databaseRecord{raw: line})
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			// The record is not echoed: a malformed shadow line can carry a password
			// hash, and an error reaches logs.
			return nil, fmt.Errorf("%s has a malformed record for %q", location, fields[0])
		}
		id, err := recordID(location, fields, idIndex)
		if err != nil {
			return nil, err
		}
		result = append(result, databaseRecord{name: fields[0], id: id, fields: fields})
	}
	return result, nil
}

// recordID reads the numeric id at idIndex, or reports zero for a database that
// has none.
func recordID(location string, fields []string, idIndex int) (uint32, error) {
	if idIndex < 0 {
		return 0, nil
	}
	if len(fields) <= idIndex {
		return 0, fmt.Errorf("%s record %q is missing its id", location, fields[0])
	}
	id, err := strconv.ParseUint(fields[idIndex], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s record %q has a non-numeric id", location, fields[0])
	}
	return uint32(id), nil
}

// writeDatabase replaces or creates one database file. Records keep their
// original field order, so an untouched line is byte-identical.
func writeDatabase(tree *vfs.Tree, file accountDatabaseFile, records database) error {
	if len(records) == 0 {
		return nil
	}
	var builder strings.Builder
	for _, record := range records {
		if record.fields == nil {
			builder.WriteString(record.raw)
		} else {
			builder.WriteString(strings.Join(record.fields, ":"))
		}
		builder.WriteString("\n")
	}
	content := []byte(builder.String())
	if _, ok := tree.Lookup(file.location); ok {
		return tree.ReplaceFile(file.location, content)
	}
	return tree.File(file.location, content, vfs.Attrs{Mode: file.mode, Origin: AccountOrigin})
}
