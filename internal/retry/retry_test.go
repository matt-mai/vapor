package retry_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/matt-mai/vapor/internal/retry"
)

var errTransient = errors.New("transient")

// policy is the default shape with a delay short enough for a test.
func policy(attempts int) retry.Policy {
	return retry.Policy{Attempts: attempts, Base: time.Millisecond, Max: 4 * time.Millisecond}
}

func TestDo_StopsAtTheFirstSuccess(t *testing.T) {
	calls := 0
	err := policy(5).Do(context.Background(), func(context.Context) (bool, error) {
		calls++
		return false, nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

func TestDo_RetriesUntilItSucceeds(t *testing.T) {
	calls := 0
	err := policy(5).Do(context.Background(), func(context.Context) (bool, error) {
		calls++
		if calls < 3 {
			return true, errTransient
		}
		return false, nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

// A failure the caller judged final must not be reissued: a missing file stays
// missing, and asking again only delays the answer.
func TestDo_DoesNotRetryAFinalFailure(t *testing.T) {
	calls := 0
	err := policy(5).Do(context.Background(), func(context.Context) (bool, error) {
		calls++
		return false, errTransient
	})
	if !errors.Is(err, errTransient) || calls != 1 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

func TestDo_GivesUpAfterItsAttempts(t *testing.T) {
	calls := 0
	err := policy(3).Do(context.Background(), func(context.Context) (bool, error) {
		calls++
		return true, errTransient
	})
	if !errors.Is(err, errTransient) || calls != 3 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

// Attempts counts the first try, so a policy of one is "no retrying", and a policy
// that somehow arrives at zero must not disable the request altogether.
func TestDo_TreatsAttemptsAsATotal(t *testing.T) {
	for _, attempts := range []int{0, 1} {
		calls := 0
		_ = retry.Policy{Attempts: attempts}.Do(context.Background(), func(context.Context) (bool, error) {
			calls++
			return true, errTransient
		})
		if calls != 1 {
			t.Fatalf("attempts %d made %d calls", attempts, calls)
		}
	}
}

func TestDo_StopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := retry.Policy{Attempts: 10, Base: time.Hour, Max: time.Hour}.Do(ctx,
		func(context.Context) (bool, error) {
			calls++
			cancel()
			return true, errTransient
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, errTransient) {
		t.Fatalf("the cause of the last attempt was dropped: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestDo_RefusesToStartWithAnEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := policy(3).Do(ctx, func(context.Context) (bool, error) {
		calls++
		return false, nil
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

// asked is a failure that names its own delay, like a rate limit telling the client
// when to come back.
type asked struct {
	delay time.Duration
	seen  *time.Duration
}

func (a *asked) Error() string { return "rate limited" }

func (a *asked) RetryAfter() time.Duration {
	if a.seen != nil {
		*a.seen = a.delay
	}
	return a.delay
}

// A server that names a delay is obeyed, even when it is longer than the backoff
// would have waited: its opinion beats a guess.
func TestDo_HonoursTheDelayAServerAsked(t *testing.T) {
	start := time.Now()
	calls := 0
	err := retry.Policy{Attempts: 2, Base: time.Millisecond, Max: 30 * time.Millisecond}.
		Do(context.Background(), func(context.Context) (bool, error) {
			calls++
			return true, &asked{delay: 25 * time.Millisecond}
		})
	if !errors.Is(err, errTransient) && err == nil {
		t.Fatal("no error after the attempts ran out")
	}
	elapsed := time.Since(start)
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if elapsed < 20*time.Millisecond {
		t.Fatalf("waited %v, which is less than the server asked for", elapsed)
	}
}

// The policy never sleeps longer than its own bound, however long the server asks
// for, so a hostile Retry-After cannot stall a command indefinitely.
func TestDo_CapsWhatAServerCanAsk(t *testing.T) {
	start := time.Now()
	_ = retry.Policy{Attempts: 2, Base: time.Millisecond, Max: 20 * time.Millisecond}.
		Do(context.Background(), func(context.Context) (bool, error) {
			return true, &asked{delay: time.Hour}
		})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("waited %v for a capped delay", elapsed)
	}
}

func TestDefault_RetriesEnoughToRideOutAThrottle(t *testing.T) {
	policy := retry.Default()
	if policy.Attempts < 3 {
		t.Fatalf("attempts = %d", policy.Attempts)
	}
	if policy.Base <= 0 || policy.Max < policy.Base {
		t.Fatalf("base = %v, max = %v", policy.Base, policy.Max)
	}
	total := time.Duration(0)
	delay := policy.Base
	for range policy.Attempts - 1 {
		if delay > policy.Max {
			delay = policy.Max
		}
		total += delay
		delay *= 2
	}
	if total < 5*time.Second || total > 5*time.Minute {
		t.Fatalf("total wait = %v, which is not a sensible window", total)
	}
}

func TestStatus(t *testing.T) {
	cases := []struct {
		status    int
		retryable bool
	}{
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
		{http.StatusRequestTimeout, true},
		// A missing or malformed request is the answer, not a hiccup.
		{http.StatusNotFound, false},
		{http.StatusForbidden, false},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusOK, false},
	}
	for _, test := range cases {
		if got := retry.Status(test.status); got != test.retryable {
			t.Errorf("Status(%d) = %v, want %v", test.status, got, test.retryable)
		}
	}
}

func TestAfter(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   time.Duration
		invert bool
	}{
		{name: "absent", header: "", want: 0},
		{name: "seconds", header: "30", want: 30 * time.Second},
		{name: "zero seconds", header: "0", want: 0},
		{name: "invalid", header: "soon", want: 0},
		{name: "negative", header: "-5", want: 0},
		{name: "past date", header: time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat), want: 0},
		{
			name:   "future date",
			header: time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat),
			invert: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{Header: http.Header{}}
			if test.header != "" {
				response.Header.Set("Retry-After", test.header)
			}
			got := retry.After(response)
			if test.invert {
				if got < 80*time.Second || got > 100*time.Second {
					t.Fatalf("After = %v", got)
				}
				return
			}
			if got != test.want {
				t.Fatalf("After = %v, want %v", got, test.want)
			}
		})
	}
}

// Two callers that fail together must not keep arriving together. The backoff is
// spread, so the delays differ without exceeding the bound.
func TestDo_SpreadsItsWaits(t *testing.T) {
	seen := make(map[time.Duration]bool)
	for range 20 {
		start := time.Now()
		_ = retry.Policy{Attempts: 2, Base: 20 * time.Millisecond, Max: 20 * time.Millisecond}.
			Do(context.Background(), func(context.Context) (bool, error) {
				return true, errTransient
			})
		elapsed := time.Since(start).Round(2 * time.Millisecond)
		seen[elapsed] = true
		if elapsed > 60*time.Millisecond {
			t.Fatalf("waited %v, which is past the bound", elapsed)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("every wait was identical: %v", seen)
	}
}
