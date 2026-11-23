package pro

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/matt-mai/vapor/internal/retry"
	"github.com/matt-mai/vapor/internal/schema/base"
)

// Fetcher requests paths from one archive. It serves the public archive as well
// as a Pro one, so its errors name the URL that failed rather than saying "Pro":
// a public archive failure blamed on Pro credentials sends the reader somewhere
// that has nothing to do with the problem.
type Fetcher struct {
	client      *http.Client
	base        *url.URL
	credentials Credentials
	policy      retry.Policy
}

// NewFetcher returns a fetcher bound to one credential-free HTTPS archive URL.
// Empty credentials are valid for public archives.
func NewFetcher(client *http.Client, archiveURL string, credentials Credentials) (*Fetcher, error) {
	if err := base.ValidateInputURL(archiveURL, true); err != nil {
		return nil, errors.New("pro archive URL must be a credential-free HTTPS URL")
	}
	baseURL, err := url.Parse(archiveURL)
	if err != nil {
		return nil, errors.New("pro archive URL is malformed")
	}
	if client == nil {
		client = &http.Client{}
	}
	return &Fetcher{
		client: client, base: baseURL, credentials: credentials,
		policy: retry.Default(),
	}, nil
}

// Fetch retrieves one clean relative path from the bound archive. Credentials
// are sent only to that archive origin.
//
// A failure that may pass — a transport error, a rate limit, a server-side error —
// is retried with the package policy. The body of a discarded attempt is drained and
// closed, so a retry does not leak a connection.
func (f *Fetcher) Fetch(ctx context.Context, relative string) (io.ReadCloser, error) {
	if ctx == nil {
		return nil, errors.New("archive fetch requires a context")
	}
	if f == nil || f.base == nil {
		return nil, errors.New("archive fetcher is not configured")
	}
	clean, err := cleanFetchPath(relative)
	if err != nil {
		return nil, err
	}
	var body io.ReadCloser
	err = f.policy.Do(ctx, func(ctx context.Context) (bool, error) {
		reader, retryable, attemptErr := f.attempt(ctx, clean)
		if attemptErr != nil {
			return retryable, attemptErr
		}
		body = reader
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

// attempt makes one request and reports whether its failure may pass on a retry.
func (f *Fetcher) attempt(ctx context.Context, clean string) (io.ReadCloser, bool, error) {
	target := *f.base
	target.Path = strings.TrimSuffix(f.base.Path, "/") + "/" + clean
	target.RawPath = ""
	target.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), http.NoBody)
	if err != nil {
		return nil, false, errors.New("build archive request")
	}
	request.Header.Set("User-Agent", "vaporize")
	if !f.credentials.Empty() {
		request.SetBasicAuth(f.credentials.username, f.credentials.password)
	}
	client := *f.client
	callerRedirect := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if redirectErr := checkProRedirect(next, via); redirectErr != nil {
			return &redirectRefusal{cause: redirectErr}
		}
		if callerRedirect != nil {
			return callerRedirect(next, via)
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		// A canceled or expired context is the caller ending the work, and a
		// refused redirect is a policy answer. Neither may pass on a retry.
		if ctx.Err() != nil {
			return nil, false, &requestError{relative: clean, cause: ctx.Err()}
		}
		if _, ok := errors.AsType[*redirectRefusal](err); ok {
			return nil, false, &requestError{relative: clean, cause: err}
		}
		return nil, true, &requestError{relative: clean, cause: err}
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, retry.Status(response.StatusCode), &requestError{
			relative: clean,
			status:   fmt.Sprintf("HTTP %d", response.StatusCode),
			retryIn:  retry.After(response),
		}
	}
	return response.Body, false, nil
}

func cleanFetchPath(relative string) (string, error) {
	if relative == "" || path.IsAbs(relative) || strings.ContainsAny(relative, "?#\\") {
		return "", errors.New("pro archive path must be relative")
	}
	cleaned := path.Clean(relative)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("pro archive path must not leave the archive")
	}
	return cleaned, nil
}

// redirectRefusal marks a redirect the fetcher refuses to follow. It is an answer,
// not a failure that may pass, so it is never retried.
type redirectRefusal struct {
	cause error
}

func (e *redirectRefusal) Error() string { return e.cause.Error() }
func (e *redirectRefusal) Unwrap() error { return e.cause }

func checkProRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many pro archive redirects")
	}
	if request.URL.Scheme != httpsScheme || request.URL.Host != via[0].URL.Host || request.URL.User != nil {
		return errors.New("pro archive redirect left its origin")
	}
	return nil
}

// requestError reports a failed archive request without exposing the archive URL,
// which may carry credentials, or the transport's own text, which may quote them.
type requestError struct {
	relative string
	status   string
	retryIn  time.Duration
	cause    error
}

// RetryAfter reports the delay a server asked for, so the retry policy can honor
// a rate limit instead of guessing.
func (e *requestError) RetryAfter() time.Duration { return e.retryIn }

func (e *requestError) Error() string {
	if e.status != "" {
		return fmt.Sprintf("archive request for %q failed: %s", e.relative, e.status)
	}
	return fmt.Sprintf("archive request for %q failed", e.relative)
}

func (e *requestError) Unwrap() error { return e.cause }
