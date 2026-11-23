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
