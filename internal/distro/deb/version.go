package deb

import (
	"cmp"
	"errors"
	"strconv"
	"strings"
)

// Version is a parsed Debian version: [epoch:]upstream[-revision]. A missing
// epoch is 0 and a missing revision is empty. Comparison treats an empty
// revision as equal to "0", matching dpkg.
type Version struct {
	Epoch    uint64
	Upstream string
	Revision string
}

// ParseVersion parses Debian's [epoch:]upstream[-revision] syntax. The epoch is
// decimal, the upstream part starts with a digit and contains only alphanumerics
// and ". + - : ~", and the revision (after the last hyphen) contains only
// alphanumerics and "+ . ~". Hyphens in the upstream part require a revision and
// colons require an epoch.
func ParseVersion(value string) (Version, error) {
	var version Version
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		epoch, err := strconv.ParseUint(value[:colon], 10, 64)
		if err != nil {
			return Version{}, errors.New("version has an invalid epoch")
		}
		version.Epoch = epoch
		value = value[colon+1:]
	}
	if hyphen := strings.LastIndexByte(value, '-'); hyphen >= 0 {
		revision := value[hyphen+1:]
		if !validVersionRevision(revision) {
			return Version{}, errors.New("version has an invalid revision")
		}
		version.Revision = revision
		value = value[:hyphen]
	}
	if !validVersionUpstream(value) {
		return Version{}, errors.New("version has an invalid upstream part")
	}
	version.Upstream = value
	return version, nil
}

// Compare returns -1, 0 or 1 when v sorts before, equal to or after other.
func (v Version) Compare(other Version) int {
	if result := cmp.Compare(v.Epoch, other.Epoch); result != 0 {
		return result
	}
	if result := compareVersionPart(v.Upstream, other.Upstream); result != 0 {
		return result
	}
	return compareVersionPart(v.Revision, other.Revision)
}

// String formats the version in its original [epoch:]upstream[-revision] form.
func (v Version) String() string {
	var value strings.Builder
	if v.Epoch != 0 {
		value.WriteString(strconv.FormatUint(v.Epoch, 10))
		value.WriteByte(':')
	}
	value.WriteString(v.Upstream)
	if v.Revision != "" {
		value.WriteByte('-')
		value.WriteString(v.Revision)
	}
	return value.String()
}

// compareVersionPart implements dpkg's verrevcmp for one version part. Digits
// compare numerically, "~" sorts before everything (including the end of the
// string), letters sort before non-letters, and other characters sort by byte
// value after letters.
func compareVersionPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		if difference, done := compareNonDigits(a, b, &i, &j); done {
			return difference
		}
		i = skipLeadingZeros(a, i)
		j = skipLeadingZeros(b, j)
		difference, nextA, nextB := compareDigits(a, b, i, j)
		i, j = nextA, nextB
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if difference != 0 {
			return cmp.Compare(difference, 0)
		}
	}
	return 0
}

func compareNonDigits(a, b string, i, j *int) (int, bool) {
	for (*i < len(a) && !isDigit(a[*i])) || (*j < len(b) && !isDigit(b[*j])) {
		left, right := 0, 0
		if *i < len(a) {
			left = versionCharacterOrder(a[*i])
		}
		if *j < len(b) {
			right = versionCharacterOrder(b[*j])
		}
		if left != right {
			return cmp.Compare(left, right), true
		}
		*i++
		*j++
	}
	return 0, false
}

func skipLeadingZeros(value string, index int) int {
	for index < len(value) && value[index] == '0' {
		index++
	}
	return index
}

func compareDigits(a, b string, i, j int) (int, int, int) {
	firstDifference := 0
	for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
		if firstDifference == 0 {
			firstDifference = int(a[i]) - int(b[j])
		}
		i++
		j++
	}
	return firstDifference, i, j
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func versionCharacterOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func validVersionUpstream(value string) bool {
	if value == "" || !isDigit(value[0]) {
		return false
	}
	for _, c := range []byte(value) {
		if !isAlphanumeric(c) && !strings.ContainsRune(".+-:~", rune(c)) {
			return false
		}
	}
	return true
}

func validVersionRevision(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		if !isAlphanumeric(c) && !strings.ContainsRune("+.~", rune(c)) {
			return false
		}
	}
	return true
}
