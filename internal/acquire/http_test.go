package acquire_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/retry"
)

func TestHTTPFetcherReadsDeclaredURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "vaporize" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		_, _ = io.WriteString(w, "payload")
	}))
	defer server.Close()
	reader, err := (acquire.HTTPFetcher{}).Fetch(t.Context(), server.URL+"/input")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload" {
		t.Fatalf("payload = %q", data)
	}
}

func TestHTTPFetcherRejectsStatus(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	_, err := (acquire.HTTPFetcher{}).Fetch(t.Context(), server.URL+"/missing")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPFetcherFollowsBoundedRedirects(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			_, _ = io.WriteString(w, "done")
			return
		}
		http.Redirect(w, r, server.URL+"/loop", http.StatusFound)
	}))
	defer server.Close()
	if _, err := (acquire.HTTPFetcher{}).Fetch(t.Context(), server.URL+"/start"); err == nil ||
		!strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPFetcherHonoursCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		close(started)
		<-t.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (acquire.HTTPFetcher{}).Fetch(ctx, server.URL+"/slow")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPFetcherRejectsInvalidURLs(t *testing.T) {
	for _, url := range []string{"file:///tmp/input", "https://user:pass@example.com/input", "https://example.com/a?token=x"} {
		if _, err := (acquire.HTTPFetcher{}).Fetch(t.Context(), url); err == nil {
			t.Fatalf("accepted %q", url)
		}
	}
}

// fast is a policy short enough for a test to exercise retrying.
func fast(attempts int) retry.Policy {
	return retry.Policy{Attempts: attempts, Base: time.Millisecond, Max: 2 * time.Millisecond}
}

// An archive that throttles a burst is the reason this exists: the same request
// must be reissued rather than failing the whole lock.
func TestHTTPFetcherRetriesATransientFailure(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "payload")
	}))
	defer server.Close()
	fetcher := acquire.HTTPFetcher{Policy: fast(5)}
	body, err := fetcher.Fetch(context.Background(), server.URL+"/input")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(body)
	if err != nil || string(data) != "payload" {
		t.Fatalf("data = %q, err = %v", data, err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d", calls)
	}
}

// A missing input is the answer. Reissuing it only delays the error.
func TestHTTPFetcherDoesNotRetryAMissingInput(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	fetcher := acquire.HTTPFetcher{Policy: fast(5)}
	if _, err := fetcher.Fetch(context.Background(), server.URL+"/missing"); err == nil {
		t.Fatal("a missing input was accepted")
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}

// A rate limit that names its own delay is obeyed, so the retry lands after the
// window the server asked for rather than inside it.
func TestHTTPFetcherObeysRetryAfter(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, "payload")
	}))
	defer server.Close()
	fetcher := acquire.HTTPFetcher{Policy: fast(5)}
	body, err := fetcher.Fetch(context.Background(), server.URL+"/throttled")
	if err != nil {
		t.Fatal(err)
	}
	_ = body.Close()
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestHTTPFetcherGivesUpAfterItsAttempts(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	fetcher := acquire.HTTPFetcher{Policy: fast(3)}
	if _, err := fetcher.Fetch(context.Background(), server.URL+"/input"); err == nil {
		t.Fatal("a failing input was accepted")
	}
	if calls != 3 {
		t.Fatalf("calls = %d", calls)
	}
}

// A GitHub release asset redirects to a signed URL, and its query is the signature
// rather than a credential: refusing it makes every release asset unfetchable. The
// target is HTTPS, which is what keeps the signature from traveling in clear text.
func TestHTTPFetcherFollowsASignedRedirect(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/asset" {
			if r.URL.RawQuery != "sp=r&sig=abc" {
				t.Errorf("redirect query = %q", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, "signed bytes")
			return
		}
		http.Redirect(w, r, server.URL+"/asset?sp=r&sig=abc", http.StatusFound)
	}))
	defer server.Close()
	reader, err := (acquire.HTTPFetcher{Client: server.Client()}).Fetch(t.Context(), server.URL+"/release")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	data, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "signed bytes" {
		t.Fatalf("payload = %q", data)
	}
}

// A redirect from one host to another must not carry the previous URL, query and all,
// as a Referer: a signed asset URL signs itself with its query.
func TestHTTPFetcherDoesNotSendARefererAcrossOrigins(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if referer := r.Header.Get("Referer"); referer != "" {
			t.Errorf("referer = %q", referer)
		}
		_, _ = io.WriteString(w, "signed bytes")
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/asset?sig=abc", http.StatusFound)
	}))
	defer source.Close()
	reader, err := (acquire.HTTPFetcher{Client: source.Client()}).Fetch(t.Context(), source.URL+"/release")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatal(err)
	}
}

// A signed target is an HTTPS target: a signature in a plaintext query is published,
// and verifying the payload's digest does not un-publish it.
func TestHTTPFetcherRefusesASignedPlaintextRedirect(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "http://example.invalid/asset?sig=abc", http.StatusFound)
	}))
	defer server.Close()
	if _, err := (acquire.HTTPFetcher{}).Fetch(t.Context(), server.URL+"/release"); err == nil ||
		!strings.Contains(err.Error(), "must be an HTTPS URL") {
		t.Fatalf("error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}

// A redirect may carry a query, but never a credential or a non-HTTP scheme.
func TestHTTPFetcherRefusesACredentialedRedirect(t *testing.T) {
	for _, target := range []string{"ftp://example.invalid/input", "https://user:pass@example.invalid/input"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
		}))
		if _, err := (acquire.HTTPFetcher{}).Fetch(t.Context(), server.URL+"/input"); err == nil {
			t.Fatalf("redirect to %q was accepted", target)
		}
		server.Close()
	}
}

// A refused redirect is a policy answer: following it would send the request
// somewhere the caller did not choose, and asking again changes nothing.
func TestHTTPFetcherDoesNotRetryARefusedRedirect(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "ftp://example.invalid/input", http.StatusFound)
	}))
	defer server.Close()
	fetcher := acquire.HTTPFetcher{Policy: fast(5)}
	if _, err := fetcher.Fetch(context.Background(), server.URL+"/input"); err == nil {
		t.Fatal("a refused redirect was accepted")
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}
