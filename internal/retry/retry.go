// Package retry reissues a request that failed for a reason that may pass.
//
// It is deliberately not a general-purpose library: it backs the two fetchers that
// talk to an archive, and nothing else retries. Deciding whether a failure may pass
// belongs to the caller, which is the only place that knows what the request was.
package retry

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

// Policy bounds how long a caller keeps asking. Attempts counts the first try, so
// Attempts of 1 disables retrying.
type Policy struct {
	Attempts int
	Base     time.Duration
	Max      time.Duration
}

// Default is the policy the fetchers use: five attempts spread over roughly a
// minute, which covers a rate limit or a short outage without stalling an
// interactive command. Public distribution archives throttle bursts, and a mirror
// rotating a backend is back within seconds.
func Default() Policy {
	return Policy{Attempts: 5, Base: 500 * time.Millisecond, Max: 20 * time.Second}
}

// Waiter is an error that asks for a specific delay, such as a rate limit naming
// its own reset time. A caller that honors it is polite to a server that told it
// exactly how long to wait.
type Waiter interface {
	RetryAfter() time.Duration
}

// Do runs attempt until it reports a final result, until the attempts run out, or
// until the context ends. attempt returns whether its failure may pass; a nil error
// always ends the loop.
func (p Policy) Do(ctx context.Context, attempt func(context.Context) (bool, error)) error {
	var last error
	for number := 1; number <= max(p.Attempts, 1); number++ {
		if err := ctx.Err(); err != nil {
			return join(last, err)
		}
		retryable, attemptErr := attempt(ctx)
		if attemptErr == nil || !retryable {
			return attemptErr
		}
		last = attemptErr
		if number == max(p.Attempts, 1) {
			return last
		}
		if waitErr := sleep(ctx, p.wait(number, last)); waitErr != nil {
			return join(last, waitErr)
		}
	}
	return last
}

// join keeps the failure that caused the attempt and the reason no more were made,
// so a cancellation does not hide what was being canceled.
func join(last, err error) error {
	if last != nil {
		return errors.Join(last, err)
	}
	return err
}

// wait is the delay before attempt number+1: exponential from Base, never above
// Max, jittered so several fetches retrying one outage do not resynchronize. A
// server that named a delay wins, because its opinion beats a guess.
func (p Policy) wait(number int, err error) time.Duration {
	delay := p.backoff(number)
	var waiter Waiter
	if errors.As(err, &waiter) {
		if asked := waiter.RetryAfter(); asked > delay {
			delay = asked
		}
	}
	if delay > p.Max {
		delay = p.Max
	}
	return delay
}

func (p Policy) backoff(number int) time.Duration {
	delay := p.Base
	for step := 1; step < number && delay < p.Max; step++ {
		delay *= 2
	}
	if delay > p.Max {
		delay = p.Max
	}
	if delay <= 0 {
		return 0
	}
	// Spread over the upper half of the interval: still bounded by Max, but two
	// callers that started together do not keep arriving together. Nothing
	// security-relevant depends on these bytes.
	half := delay / 2
	if half <= 0 {
		return delay
	}
	return half + time.Duration(rand.Int64N(int64(half)+1)) //nolint:gosec // jitter only
}

func sleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
