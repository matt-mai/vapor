package ui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type gatedWriter struct {
	buffer  bytes.Buffer
	entered chan struct{}
	release chan struct{}
	writes  atomic.Int64
	cause   error
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	if w.writes.Add(1) == 2 {
		close(w.entered)
		<-w.release
		if w.cause != nil {
			return 0, w.cause
		}
	}
	return w.buffer.Write(p)
}

func TestReporter_StopJoinsInFlightWrite(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "successful write"
		if failure {
			name = "failed write"
		}
		t.Run(name, func(t *testing.T) {
			out := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
			if failure {
				out.cause = errors.New("write failed")
			}
			ticks := make(chan time.Time)
			cfg := testConfig(out, true, nil)
			cfg.Ticks = ticks
			r := New(t.Context(), cfg)
			if err := r.Update(&Phase{Number: 1, Total: 1, Title: "work"}); err != nil {
				t.Fatal(err)
			}
			ticks <- time.Time{}
			<-out.entered
			started := make(chan struct{})
			result := make(chan error, 1)
			go func() { close(started); result <- r.Stop() }()
			<-started
			select {
			case err := <-result:
				t.Fatalf("Stop returned during blocked write: %v", err)
			default:
			}
			close(out.release)
			if err := <-result; !errors.Is(err, out.cause) {
				t.Fatalf("got %v, want %v", err, out.cause)
			}
			select {
			case <-r.done:
			default:
				t.Fatal("Stop did not join worker")
			}
			count, text := out.writes.Load(), out.buffer.String()
			close(ticks)
			if err := r.Stop(); !errors.Is(err, out.cause) {
				t.Fatal(err)
			}
			if out.writes.Load() != count || out.buffer.String() != text {
				t.Fatal("post-stop write")
			}
		})
	}
}

func TestReporter_CancellationStopsActiveWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var out bytes.Buffer
	ticks := make(chan time.Time)
	cfg := testConfig(&out, true, nil)
	cfg.Ticks = ticks
	r := New(ctx, cfg)
	if err := r.Update(&Phase{Target: "target", Number: 1, Total: 1, Title: "active"}); err != nil {
		t.Fatal(err)
	}
	cancel()
	// Waiting before Stop proves the worker handles cancellation autonomously.
	<-r.done
	if !strings.Contains(out.String(), "canceled [target] [1/1] active: operation canceled\n") {
		t.Fatal(out.String())
	}
	before := out.String()
	if err := r.Stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(ticks)
	if err := r.Update(&Phase{Number: 1, Total: 1}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if before != out.String() {
		t.Fatal("post-cancellation output")
	}
}
