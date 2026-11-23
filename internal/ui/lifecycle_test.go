package ui

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestReporter_AlreadyCanceled(t *testing.T) {
	for _, method := range []string{"update", "success", "fail", "stop"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var out bytes.Buffer
			r := New(ctx, testConfig(&out, false, nil))
			var err error
			switch method {
			case "update":
				err = r.Update(&Phase{Number: 1, Total: 1})
			case "success":
				err = r.Success(&Summary{})
			case "fail":
				err = r.Fail(Failure{Message: "failed"})
			case "stop":
				err = r.Stop()
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if err := r.Stop(); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if out.String() != "canceled: operation canceled\n" {
				t.Fatal(out.String())
			}
		})
	}
}

func TestReporter_TickerOwnership(t *testing.T) {
	// Exercise the owned ticker without relying on any tick firing.
	r := New(t.Context(), testConfig(&bytes.Buffer{}, true, nil))
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.done:
	default:
		t.Fatal("worker not joined")
	}
	// Closing an injected tick channel must not stop context cancellation handling.
	ticks := make(chan time.Time)
	close(ticks)
	ctx, cancel := context.WithCancel(t.Context())
	cfg := testConfig(&bytes.Buffer{}, true, nil)
	cfg.Ticks = ticks
	r = New(ctx, cfg)
	cancel()
	<-r.done
	if err := r.Stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReporter_DefaultDependencies(t *testing.T) {
	// No writes: exercise defaults without depending on the process's stderr or env.
	r := New(t.Context(), &Config{})
	if r.animated {
		t.Fatal("nil terminal detector must be conservative")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestReporter_ConcurrentTerminalStop(t *testing.T) {
	var out bytes.Buffer
	ticks := make(chan time.Time, 100)
	for range 100 {
		ticks <- time.Time{}
	}
	cfg := testConfig(&out, true, nil)
	cfg.Ticks = ticks
	r := New(t.Context(), cfg)
	if err := r.Update(&Phase{Number: 1, Total: 1}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 10)
	for range 10 {
		go func() { results <- r.Stop() }()
	}
	for range 10 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	before := out.String()
	if err := r.Success(&Summary{}); err != nil {
		t.Fatal(err)
	}
	if out.String() != before {
		t.Fatal("output after joined stop")
	}
}
