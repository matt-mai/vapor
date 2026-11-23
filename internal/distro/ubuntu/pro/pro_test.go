package pro

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/retry"
)

func writeAuthFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCredentials(t *testing.T) {
	dir := t.TempDir()
	archive := "https://esm.example.com/apps/ubuntu/"
	writeAuthFile(t, dir, "10-other.conf", "machine https://other.example.com login other password other-secret\n")
	writeAuthFile(t, dir, ".hidden", "machine "+archive+" login hidden password hidden-secret\n")
	writeAuthFile(t, dir, "notes.txt", "machine "+archive+" login text password text-secret\n")
	writeAuthFile(t, dir, "20-pro.conf", "machine "+archive+" login token password pro-secret\n")
	credentials, err := LoadCredentials(archive+"dists/resolute/InRelease", dir)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Empty() {
		t.Fatal("credentials not loaded")
	}
	if strings.Contains(credentials.String(), "token") || strings.Contains(credentials.String(), "pro-secret") {
		t.Fatalf("credentials formatted unsafely: %q", credentials.String())
	}
	if formatted := fmt.Sprintf("%#v", credentials); strings.Contains(formatted, "pro-secret") {
		t.Fatalf("credentials formatted unsafely: %q", formatted)
	}
	loginOnly := t.TempDir()
	writeAuthFile(t, loginOnly, "auth.conf", "machine "+archive+" login token\n")
	if credentials, err := LoadCredentials(archive, loginOnly); err != nil || credentials.Empty() {
		t.Fatalf("login-only credentials: %v, %v", credentials, err)
	}
}

func TestLoadCredentialsIgnoresCommentedMachines(t *testing.T) {
	dir := t.TempDir()
	archive := "https://esm.example.com/apps/ubuntu/"
	writeAuthFile(t, dir, "auth.conf", "# machine "+archive+" login retired password old-secret\n"+
		"machine "+archive+" login token password active-secret # current token\n")
	credentials, err := LoadCredentials(archive, dir)
	if err != nil {
		t.Fatal(err)
	}
	if credentials != (Credentials{username: "token", password: "active-secret"}) {
		t.Fatalf("credentials = %#v", credentials)
	}
}

func TestLoadCredentialsIgnoresUnmatchedMachines(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, "auth.conf", "machine https://esm.example.com/apps/other login token password secret\n")
	_, err := LoadCredentials("https://esm.example.com/apps/ubuntu/", dir)
	if !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadCredentialsMissing(t *testing.T) {
	if _, err := LoadCredentials("https://esm.example.com/apps/ubuntu/", t.TempDir()); !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("error = %v", err)
	}
	if _, err := LoadCredentials("https://esm.example.com/apps/ubuntu/", filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("missing directory error = %v", err)
	}
}

func TestLoadCredentialsRejectsInvalidEntries(t *testing.T) {
	archive := "https://esm.example.com/apps/ubuntu/"
	cases := []struct {
		name    string
		content string
	}{
		{name: "missing login", content: "machine " + archive + " password secret\n"},
		{name: "missing value", content: "machine\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeAuthFile(t, dir, "auth.conf", tc.content)
			_, err := LoadCredentials(archive, dir)
			if err == nil || errors.Is(err, ErrCredentialsNotFound) {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaks credentials: %v", err)
			}
		})
	}
}

func TestLoadCredentialsRejectsNonHTTPS(t *testing.T) {
	if _, err := LoadCredentials("http://esm.example.com/apps/ubuntu/", t.TempDir()); err == nil {
		t.Fatal("http archive URL was accepted")
	}
}

func clearCredentialsEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv(EnvUsername, "")
	t.Setenv(EnvPassword, "")
}

func TestLoadDefaultCredentials(t *testing.T) {
	clearCredentialsEnvironment(t)
	dir := t.TempDir()
	archive := "https://esm.example.com/apps/ubuntu/"
	writeAuthFile(t, dir, "auth.conf", "machine "+archive+" login token password secret\n")
	t.Setenv("VAPOR_AUTH_DIR", dir)
	if _, err := LoadDefaultCredentials(archive); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDefaultCredentialsFromEnvironment(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "env-user" || password != "env-pass" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(writer, "environment")
	}))
	defer server.Close()
	dir := t.TempDir()
	writeAuthFile(t, dir, "auth.conf", "machine "+server.URL+" login file-user password file-pass\n")
	t.Setenv("VAPOR_AUTH_DIR", dir)
	t.Setenv(EnvUsername, "env-user")
	t.Setenv(EnvPassword, "env-pass")
	credentials, err := LoadDefaultCredentials(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewFetcher(server.Client(), server.URL, credentials)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := fetcher.Fetch(context.Background(), "dists/resolute/InRelease")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "environment" {
		t.Fatalf("body = %q", body)
	}
}

func TestLoadDefaultCredentialsRejectsIncompleteEnvironment(t *testing.T) {
	clearCredentialsEnvironment(t)
	t.Setenv(EnvPassword, "env-secret")
	if _, err := LoadDefaultCredentials("https://esm.example.com/apps/ubuntu/"); err == nil {
		t.Fatal("password without username was accepted")
	} else if strings.Contains(err.Error(), "env-secret") {
		t.Fatalf("error leaked a secret: %v", err)
	}
}

func TestLoadDefaultCredentialsFromEnvironmentNeedsNoDirectory(t *testing.T) {
	t.Setenv("VAPOR_AUTH_DIR", filepath.Join(t.TempDir(), "missing"))
	t.Setenv(EnvUsername, "env-user")
	t.Setenv(EnvPassword, "")
	if _, err := LoadDefaultCredentials("https://esm.example.com/apps/ubuntu/"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDefaultCredentialsFromEnvironmentValidatesURL(t *testing.T) {
	t.Setenv(EnvUsername, "env-user")
	if _, err := LoadDefaultCredentials("http://esm.example.com/apps/ubuntu/"); err == nil {
		t.Fatal("http archive URL was accepted")
	}
}

func TestFetcherPublicArchiveNeedsNoCredentials(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, _, ok := request.BasicAuth(); ok {
			t.Error("public archive request had authorization")
		}
		_, _ = io.WriteString(writer, "public release")
	}))
	defer server.Close()
	fetcher, err := NewFetcher(server.Client(), server.URL, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := fetcher.Fetch(context.Background(), "dists/resolute/InRelease")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "public release" {
		t.Fatalf("body = %q", body)
	}
}

func TestFetcherSendsBasicAuth(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "token" || password != "pro-secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(writer, "authenticated")
	}))
	defer server.Close()
	dir := t.TempDir()
	writeAuthFile(t, dir, "auth.conf", "machine "+server.URL+" login token password pro-secret\n")
	credentials, err := LoadCredentials(server.URL+"/dists/resolute/InRelease", dir)
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := NewFetcher(server.Client(), server.URL, credentials)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := fetcher.Fetch(context.Background(), "dists/resolute/InRelease")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "authenticated" {
		t.Fatalf("body = %q", body)
	}
}

func TestFetcherRejectsInvalidCredentialsWithoutLeak(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	fetcher, err := NewFetcher(server.Client(), server.URL, Credentials{username: "token", password: "pro-secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetcher.Fetch(context.Background(), "dists/resolute/InRelease")
	if err == nil {
		t.Fatal("unauthorized request succeeded")
	}
	if strings.Contains(err.Error(), "pro-secret") || strings.Contains(err.Error(), "token") {
		t.Fatalf("error leaks credentials: %v", err)
	}
}

func TestFetcherRejectsInvalidPaths(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	fetcher, err := NewFetcher(server.Client(), server.URL, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "../secret", "/absolute", "a?query", `a\b`} {
		if _, err := fetcher.Fetch(context.Background(), path); err == nil {
			t.Fatalf("path %q was accepted", path)
		}
	}
}

func TestFetcherRejectsCrossOriginRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://example.com/InRelease", http.StatusFound)
	}))
	defer server.Close()
	fetcher, err := NewFetcher(server.Client(), server.URL, Credentials{username: "token", password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetcher.Fetch(context.Background(), "dists/resolute/InRelease")
	if err == nil {
		t.Fatal("cross-origin redirect was followed")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks credentials: %v", err)
	}
}

// The fetcher serves the public archive too. A failure there must not blame Pro
// credentials, and it must say what failed, or a reader is sent looking for a
// subscription that has nothing to do with the problem.
func TestFetcherPublicArchiveFailureNamesTheRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	fetcher, err := NewFetcher(server.Client(), server.URL, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	// One attempt: the message, not the policy, is what this test is about.
	fetcher.policy = retry.Policy{Attempts: 1}
	_, err = fetcher.Fetch(context.Background(), "dists/resolute/InRelease")
	if err == nil {
		t.Fatal("a failing archive returned no error")
	}
	message := err.Error()
	for _, wrong := range []string{"pro", "Pro", "credential"} {
		if strings.Contains(message, wrong) {
			t.Fatalf("public archive failure mentions %q: %s", wrong, message)
		}
	}
	for _, want := range []string{"archive request", "dists/resolute/InRelease", "HTTP 503"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message is missing %q: %s", want, message)
		}
	}
	if strings.Contains(message, server.URL) {
		t.Fatalf("message leaks the archive URL: %s", message)
	}
}
