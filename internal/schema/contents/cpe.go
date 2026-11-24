package contents

import "strings"

// SplitCPE splits a CPE 2.3 formatted name on the colons that are not escaped. A field
// may carry `\:`, so counting every colon would read one field as two and hand a
// scanner a name it cannot parse. Fields are returned as written, so joining them again
// reproduces the name byte for byte.
func SplitCPE(value string) []string {
	fields := make([]string, 0, 13)
	var field strings.Builder
	for index := 0; index < len(value); index++ {
		switch char := value[index]; {
		case char == '\\' && index+1 < len(value):
			// An escape belongs to the field it is written in, so it is kept as it is.
			field.WriteByte(char)
			index++
			field.WriteByte(value[index])
		case char == ':':
			fields = append(fields, field.String())
			field.Reset()
		default:
			field.WriteByte(char)
		}
	}
	return append(fields, field.String())
}

// EscapeCPEField renders a literal value as one CPE field. A colon would change the
// field count, and a bare backslash or wildcard would turn the value into an escape or a
// logical value, so all four are escaped.
func EscapeCPEField(value string) string {
	var escaped strings.Builder
	for _, char := range value {
		switch char {
		case '\\', ':', '*', '?':
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(char)
	}
	return escaped.String()
}
