// Package pro authenticates selected Ubuntu Pro archive requests with
// credentials from APT auth configuration.
package pro

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// DefaultAuthDir is APT's per-machine credential directory.
const DefaultAuthDir = "/etc/apt/auth.conf.d"

// Environment variables that replace credential-file lookup when set.
const (
	EnvUsername = "VAPOR_PRO_USERNAME"
	EnvPassword = "VAPOR_PRO_PASSWORD" //nolint:gosec // Environment variable name, not a secret.
)

// MaxAuthFileSize bounds one APT auth configuration file.
const MaxAuthFileSize int64 = 1 << 20

const httpsScheme = "https"

// ErrCredentialsNotFound reports that no entry matches the selected archive.
var ErrCredentialsNotFound = errors.New("pro archive credentials not found")

// Credentials hold one APT machine login. Values remain in memory only and are
// redacted from formatting.
type Credentials struct {
	username string
	password string
}

// Empty reports whether the entry has no login.
func (c Credentials) Empty() bool {
	return c.username == "" && c.password == ""
}

// String implements fmt.Stringer without exposing either value.
func (c Credentials) String() string { return "pro credentials [redacted]" }

// GoString implements fmt.GoStringer without exposing either value.
func (c Credentials) GoString() string { return c.String() }

// LoadDefaultCredentials uses VAPOR_PRO_USERNAME/VAPOR_PRO_PASSWORD when the
// username is set, replacing credential-file lookup. Otherwise it searches
// VAPOR_AUTH_DIR, or DefaultAuthDir when unset.
func LoadDefaultCredentials(archiveURL string) (Credentials, error) {
	if _, err := credentialsQueryFor(archiveURL); err != nil {
		return Credentials{}, err
	}
	username := os.Getenv(EnvUsername)
	password := os.Getenv(EnvPassword)
	if username != "" {
		return Credentials{username: username, password: password}, nil
	}
	if password != "" {
		return Credentials{}, errors.New("pro credentials environment is incomplete")
	}
	dir := os.Getenv("VAPOR_AUTH_DIR")
	if dir == "" {
		dir = DefaultAuthDir
	}
	return LoadCredentials(archiveURL, dir)
}

// LoadCredentials returns the first matching machine entry for archiveURL.
// Files are searched in lexical order. A missing directory or unmatched entry
// reports ErrCredentialsNotFound.
func LoadCredentials(archiveURL, authDir string) (Credentials, error) {
	query, err := credentialsQueryFor(archiveURL)
	if err != nil {
		return Credentials{}, err
	}
	if authDir == "" {
		return Credentials{}, ErrCredentialsNotFound
	}
	entries, err := os.ReadDir(authDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Credentials{}, ErrCredentialsNotFound
		}
		return Credentials{}, errors.New("cannot read pro credentials directory")
	}
	for _, entry := range entries {
		if !authFileCandidate(entry) {
			continue
		}
		credentials, matched, err := credentialsFromFile(filepath.Join(authDir, entry.Name()), query)
		if err != nil {
			return Credentials{}, err
		}
		if matched {
			return credentials, nil
		}
	}
	return Credentials{}, ErrCredentialsNotFound
}

func authFileCandidate(entry fs.DirEntry) bool {
	name := entry.Name()
	if strings.HasPrefix(name, ".") || entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
		return false
	}
	ext := filepath.Ext(name)
	return ext == "" || ext == ".conf"
}

func credentialsFromFile(path string, query credentialsQuery) (Credentials, bool, error) {
	//nolint:gosec // path is a directory entry name from ReadDir, not caller text.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Credentials{}, false, nil
	}
	if info.Size() > MaxAuthFileSize {
		return Credentials{}, false, errors.New("pro credentials file is too large")
	}
	//nolint:gosec // path is a directory entry name from ReadDir, not caller text.
	file, err := os.Open(path)
	if err != nil {
		return Credentials{}, false, errors.New("cannot read pro credentials file")
	}
	defer func() { _ = file.Close() }()
	return parseAuthFile(io.LimitReader(file, MaxAuthFileSize+1), query)
}

func parseAuthFile(reader io.Reader, query credentialsQuery) (Credentials, bool, error) {
	tokens := newAuthTokens(reader)
	var entry authParse
	for {
		token, ok := tokens.next()
		if !ok {
			break
		}
		done, err := entry.consume(tokens, token, query)
		if err != nil {
			return Credentials{}, false, err
		}
		if done {
			return entry.credentials()
		}
	}
	if err := tokens.err(); err != nil {
		return Credentials{}, false, errors.New("pro credentials file is malformed")
	}
	if entry.matched {
		return entry.credentials()
	}
	return Credentials{}, false, nil
}

// authTokens yields whitespace-separated tokens, dropping full-line and
// trailing comments. APT auth files use '#' for both.
type authTokens struct {
	scanner *bufio.Scanner
	pending []string
	errVal  error
}

func newAuthTokens(reader io.Reader) *authTokens {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	scanner.Split(bufio.ScanLines)
	return &authTokens{scanner: scanner}
}

func (tokens *authTokens) next() (string, bool) {
	for len(tokens.pending) == 0 {
		if tokens.errVal != nil || !tokens.scanner.Scan() {
			return "", false
		}
		tokens.pending = authLineFields(tokens.scanner.Text())
	}
	token := tokens.pending[0]
	tokens.pending = tokens.pending[1:]
	return token, true
}

func (tokens *authTokens) err() error {
	if tokens.errVal != nil {
		return tokens.errVal
	}
	return tokens.scanner.Err()
}

func authLineFields(line string) []string {
	fields := strings.Fields(line)
	for i := range fields {
		if strings.HasPrefix(fields[i], "#") {
			return fields[:i]
		}
	}
	return fields
}

type authParse struct {
	matched  bool
	login    string
	password string
}

func (p *authParse) consume(tokens *authTokens, token string, query credentialsQuery) (bool, error) {
	if token != "machine" {
		return false, p.readCredential(tokens, token)
	}
	if p.matched {
		return true, nil
	}
	return false, p.readMachine(tokens, query)
}

func (p *authParse) credentials() (Credentials, bool, error) {
	return authEntry(p.login, p.password)
}

func (p *authParse) readMachine(tokens *authTokens, query credentialsQuery) error {
	machine, ok := tokens.next()
	if !ok {
		return errors.New("pro credentials file is malformed")
	}
	parsed, ok := parseMachine(machine)
	p.matched = ok && parsed.matches(query)
	p.login, p.password = "", ""
	return nil
}

func (p *authParse) readCredential(tokens *authTokens, token string) error {
	if !p.matched {
		return nil
	}
	switch token {
	case "login":
		return readAuthValue(tokens, &p.login)
	case "password":
		return readAuthValue(tokens, &p.password)
	}
	return nil
}

func readAuthValue(tokens *authTokens, target *string) error {
	value, ok := tokens.next()
	if !ok {
		return errors.New("pro credentials file is malformed")
	}
	*target = value
	return nil
}

func authEntry(login, password string) (Credentials, bool, error) {
	if login == "" {
		return Credentials{}, false, errors.New("pro credentials entry is incomplete")
	}
	return Credentials{username: login, password: password}, true, nil
}

type credentialsQuery struct {
	scheme string
	host   string
	port   string
	path   string
}

func credentialsQueryFor(archiveURL string) (credentialsQuery, error) {
	if err := base.ValidateInputURL(archiveURL, true); err != nil {
		return credentialsQuery{}, errors.New("pro archive URL must be a credential-free HTTPS URL")
	}
	parsed, err := url.Parse(archiveURL)
	if err != nil {
		return credentialsQuery{}, errors.New("pro archive URL is malformed")
	}
	return credentialsQuery{
		scheme: parsed.Scheme,
		host:   strings.ToLower(parsed.Hostname()),
		port:   normalizedPort(parsed),
		path:   parsed.Path,
	}, nil
}

func parseMachine(value string) (credentialsQuery, bool) {
	if !strings.Contains(value, "://") {
		value = httpsScheme + "://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != httpsScheme || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return credentialsQuery{}, false
	}
	return credentialsQuery{
		scheme: parsed.Scheme,
		host:   strings.ToLower(parsed.Hostname()),
		port:   normalizedPort(parsed),
		path:   parsed.Path,
	}, true
}

func normalizedPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if value.Scheme == "https" {
		return "443"
	}
	return ""
}

func (m credentialsQuery) matches(archive credentialsQuery) bool {
	if m.scheme != archive.scheme || m.host != archive.host || m.port != archive.port {
		return false
	}
	machinePath := strings.TrimSuffix(m.path, "/")
	archivePath := strings.TrimSuffix(archive.path, "/")
	return machinePath == "" || archivePath == machinePath ||
		strings.HasPrefix(archivePath, machinePath+"/")
}
