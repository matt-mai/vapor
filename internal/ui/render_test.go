package ui

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type observedWriter struct {
	buffer bytes.Buffer
	writes chan struct{}
	fail   atomic.Bool
	cause  error
}

func (w *observedWriter) String() string { return w.buffer.String() }

func (w *observedWriter) Write(p []byte) (int, error) {
	if w.fail.Load() {
		return 0, w.cause
	}
	n, err := w.buffer.Write(p)
	w.writes <- struct{}{}
	return n, err
}

func TestReporter_InjectedTicksAndClock(t *testing.T) {
	out := &observedWriter{writes: make(chan struct{}, 10)}
	ticks := make(chan time.Time)
	cfg := testConfig(out, true, map[string]string{"NO_COLOR": "1"})
	cfg.Ticks = ticks
	var seconds atomic.Int64
	cfg.Now = func() time.Time { return time.Unix(seconds.Load(), 0) }
	r := New(t.Context(), cfg)
	if err := r.Update(&Phase{Target: "target", Number: 1, Total: 1, Title: "work"}); err != nil {
		t.Fatal(err)
	}
	<-out.writes
	seconds.Store(3)
	ticks <- time.Time{}
	<-out.writes
	for range 10 {
		ticks <- time.Time{}
		<-out.writes
	}
	if err := r.Warning("diagnostic"); err != nil {
		t.Fatal(err)
	}
	if err := r.CompletePhase(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"⠋ [1/1] work 0s", "⠙ [1/1] work 3s", "warning [target] [1/1] work: diagnostic\n\r\x1b[2K⠙", "✓ [target] [1/1] work"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	for _, frame := range []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"} {
		if !strings.Contains(text, frame+" [1/1] work 3s") {
			t.Fatalf("missing frame %s in %q", frame, text)
		}
	}
	before := out.String()
	close(ticks)
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if out.String() != before {
		t.Fatal("tick after stop")
	}
}

type brokenWriter struct {
	short bool
	cause error
}

func (w brokenWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.cause
}

func TestReporter_WriteFailures(t *testing.T) {
	cause := errors.New("secret writer error")
	for _, tc := range []struct {
		name   string
		writer io.Writer
		want   error
	}{
		{"error", brokenWriter{cause: cause}, cause},
		{"short write", brokenWriter{short: true}, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(t.Context(), testConfig(tc.writer, false, nil))
			err := r.Update(&Phase{Number: 1, Total: 1})
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe or missing cause: %v", err)
			}
			if err := r.Stop(); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if err := r.Stop(); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
}

func TestReporter_TickWriteFailure(t *testing.T) {
	cause := errors.New("tick write failed")
	out := &observedWriter{writes: make(chan struct{}, 2), cause: cause}
	ticks := make(chan time.Time)
	cfg := testConfig(out, true, nil)
	cfg.Ticks = ticks
	r := New(t.Context(), cfg)
	if err := r.Update(&Phase{Number: 1, Total: 1}); err != nil {
		t.Fatal(err)
	}
	<-out.writes
	out.fail.Store(true)
	ticks <- time.Time{}
	<-r.done
	if err := r.Stop(); !errors.Is(err, cause) {
		t.Fatal(err)
	}
}

func TestReporter_ShutdownWriteFailure(t *testing.T) {
	for _, method := range []string{"stop", "fail", "success", "complete", "log"} {
		t.Run(method, func(t *testing.T) {
			cause := errors.New("output failed")
			out := &observedWriter{writes: make(chan struct{}, 4), cause: cause}
			cfg := testConfig(out, false, nil)
			r := New(t.Context(), cfg)
			if err := r.Update(&Phase{Number: 1, Total: 1}); err != nil {
				t.Fatal(err)
			}
			out.fail.Store(true)
			var err error
			switch method {
			case "stop":
				err = r.Stop()
			case "fail":
				err = r.Fail(Failure{Message: "failed"})
			case "success":
				err = r.Success(&Summary{})
			case "complete":
				err = r.CompletePhase()
			case "log":
				err = r.Warning("detail")
			}
			if !errors.Is(err, cause) {
				t.Fatal(err)
			}
			if err := r.Stop(); !errors.Is(err, cause) {
				t.Fatal(err)
			}
		})
	}
}
