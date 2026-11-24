package acquire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/matt-mai/vapor/internal/retry"
	"github.com/matt-mai/vapor/internal/schema/base"
)

const userAgent = "vaporize"

// HTTPFetcher retrieves declared input URLs without credentials.
type HTTPFetcher struct {
	// Client may supply transport, timeout and proxy policy. Redirect handling
	// remains restricted when it is nil.
	Client *http.Client
	// Policy bounds retries. The zero value means DefaultPolicy.
	Policy retry.Policy
}

// Fetch requests one credential-free HTTP(S) URL.
func (f HTTPFetcher) Fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	if ctx == nil {
		return nil, errors.New("fetch requires a context")
	}
	if err := base.ValidateInputURL(url, false); err != nil {
		return nil, err
	}
	client := &http.Client{}
	if f.Client != nil {
		*client = *f.Client
	}
	client.CheckRedirect = redirectPolicy(client.CheckRedirect)
	policy := f.Policy
	if policy.Attempts <= 0 {
		policy = retry.Default()
	}
	var body io.ReadCloser
	err := policy.Do(ctx, func(ctx context.Context) (bool, error) {
		reader, retryable, attemptErr := attempt(ctx, client, url)
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
func attempt(ctx context.Context, client *http.Client, url string) (io.ReadCloser, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, false, errors.New("build download request")
	}
	request.Header.Set("User-Agent", userAgent)
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if _, ok := errors.AsType[*redirectRefusal](err); ok {
			return nil, false, err
		}
		return nil, true, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, retry.Status(response.StatusCode), &statusError{
			status:  response.StatusCode,
			retryIn: retry.After(response),
		}
	}
	return response.Body, false, nil
}

// statusError reports a non-success response and the delay the server asked for.
type statusError struct {
	status  int
	retryIn time.Duration
}

func (e *statusError) Error() string {
	return fmt.Sprintf("download returned HTTP status %d", e.status)
}

// RetryAfter reports the delay a server asked for, so a rate limit is honored
// rather than guessed at.
func (e *statusError) RetryAfter() time.Duration { return e.retryIn }

// redirectRefusal marks a redirect the fetcher refuses to follow. It is an answer,
// not a failure that may pass, so it is never retried.
type redirectRefusal struct {
	cause error
}

func (e *redirectRefusal) Error() string { return e.cause.Error() }
func (e *redirectRefusal) Unwrap() error { return e.cause }

// redirectPolicy bounds and filters redirects, then hands the decision to the
// caller's own policy when there is one.
func redirectPolicy(caller func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if err := checkRedirect(request, via); err != nil {
			return &redirectRefusal{cause: err}
		}
		if caller != nil {
			if err := caller(request, via); err != nil {
				return err
			}
		}
		// Go fills in a Referer from the previous hop, and a signed asset URL keeps
		// its signature in the query. A build request has no referring page, so no
		// hop is told where the last one came from.
		request.Header.Del("Referer")
		return nil
	}
}

func checkRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	// A declared input URL carries no query, but a redirect to a signed asset URL
	// does; the target is never recorded or printed with its query.
	return base.ValidateRedirectURL(request.URL.String())
}
