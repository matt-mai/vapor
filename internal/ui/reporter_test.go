package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(out io.Writer, terminal bool, env map[string]string) *Config {
	return &Config{Stderr: out, Terminal: func() bool { return terminal },
		Getenv: func(key string) string { return env[key] }, Now: func() time.Time { return time.Unix(100, 0) }}
}

func TestReporter_Modes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		terminal        bool
		env             map[string]string
		animated, color bool
	}{
		{"terminal", true, nil, true, true},
		{"no color", true, map[string]string{"NO_COLOR": "1"}, true, false},
		{"CI", true, map[string]string{"CI": "true"}, false, false},
		{"CI false is set", true, map[string]string{"CI": "false"}, false, false},
		{"dumb", true, map[string]string{"TERM": "dumb"}, false, false},
		{"redirected", false, nil, false, false},
		{"redirected no color", false, map[string]string{"NO_COLOR": "1"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			cfg := testConfig(&out, tc.terminal, tc.env)
			cfg.Ticks = make(chan time.Time)
			r := New(t.Context(), cfg)
			if err := r.Update(&Phase{Target: "linux/amd64", Number: 1, Total: 3, Title: "Verify", Details: "8/14 packages"}); err != nil {
				t.Fatal(err)
			}
			if err := r.CompletePhase(); err != nil {
				t.Fatal(err)
			}
			if err := r.Stop(); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			if strings.Contains(text, "vaporize") {
				t.Fatalf("unexpected branding: %q", text)
			}
			if strings.Contains(text, "\r\x1b[2K") != tc.animated || strings.Contains(text, "\x1b[36m") != tc.color {
				t.Fatalf("wrong mode: %q", text)
			}
			if !strings.Contains(text, "✓ [linux/amd64] [1/3] Verify — 8/14 packages") {
				t.Fatal(text)
			}
			if !tc.animated && (strings.ContainsAny(text, "\x1b\r") || strings.Contains(text, "0s")) {
				t.Fatal(text)
			}
		})
	}
}

func TestReporter_PlainStable(t *testing.T) {
	render := func(now int64) string {
		var out bytes.Buffer
		cfg := testConfig(&out, false, nil)
		cfg.Now = func() time.Time { return time.Unix(now, 0) }
		r := New(t.Context(), cfg)
		for _, err := range []error{
			r.Update(&Phase{Target: "linux/arm64", Number: 2, Total: 3, Title: "Assemble"}),
			r.Warning("verified 12 files"), r.CompletePhase(),
			r.Success(&Summary{Target: "app", Image: "demo:v1", Platforms: []string{"linux/arm64"}, Layers: 2,
				UncompressedBytes: 42, Attestations: []string{"sbom"}, Destination: "app.oci"}),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
		return out.String()
	}
	got := render(100)
	if got != render(900) {
		t.Fatal("plain output depends on clock")
	}
	want := "running [linux/arm64] [2/3] Assemble\n" +
		"warning [linux/arm64] [2/3] Assemble: verified 12 files\n" +
		"✓ [linux/arm64] [2/3] Assemble\n" +
		"success: target=app image=demo:v1 platforms=linux/arm64 layers=2 uncompressed=42 B attestations=sbom destination=app.oci\n"
	if got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestReporter_FailureAndStop(t *testing.T) {
	var out bytes.Buffer
	r := New(t.Context(), testConfig(&out, false, nil))
	if err := r.Update(&Phase{Target: "linux/amd64", Number: 1, Total: 2, Title: "Verify"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Fail(Failure{Message: "digest mismatch", Guidance: "restore verified cached inputs"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "failed [linux/amd64] [1/2] Verify: digest mismatch; restore verified cached inputs\n") {
		t.Fatal(out.String())
	}
	before := out.String()
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Update(&Phase{}); !errors.Is(err, ErrStopped) {
		t.Fatal(err)
	}
	if err := r.Warning("late"); !errors.Is(err, ErrStopped) {
		t.Fatal(err)
	}
	if err := r.CompletePhase(); !errors.Is(err, ErrStopped) {
		t.Fatal(err)
	}
	if err := r.Fail(Failure{Message: "late"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != before {
		t.Fatal("post-stop output")
	}
}

func TestReporter_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var out bytes.Buffer
	cfg := testConfig(&out, true, nil)
	cfg.Ticks = make(chan time.Time)
	r := New(ctx, cfg)
	if err := r.Update(&Phase{Target: "target", Number: 1, Total: 1, Title: "Work"}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := r.Stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "canceled [target] [1/1] Work: operation canceled") {
		t.Fatal(out.String())
	}
	before := out.String()
	if err := r.Warning("late"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := r.Stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if before != out.String() {
		t.Fatal("post-cancel output")
	}
}

func TestReporter_ConcurrentUpdatesAndStop(t *testing.T) {
	var out bytes.Buffer
	cfg := testConfig(&out, false, nil)
	r := New(t.Context(), cfg)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 20 {
				if err := r.Update(&Phase{Target: "target", Number: 1, Total: 1, Title: "work"}); err != nil && !errors.Is(err, ErrStopped) {
					t.Error(err)
				}
				if err := r.Warning("detail"); err != nil && !errors.Is(err, ErrStopped) {
					t.Error(err)
				}
			}
		})
	}
	wg.Go(func() {
		if err := r.Stop(); err != nil {
			t.Error(err)
		}
	})
	wg.Wait()
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		if line != "" && !strings.HasPrefix(line, "running ") && !strings.HasPrefix(line, "warning ") && !strings.HasPrefix(line, "stopped ") {
			t.Fatalf("interleaved line %q", line)
		}
	}
}

func TestReporter_InvalidCounters(t *testing.T) {
	var out bytes.Buffer
	r := New(t.Context(), testConfig(&out, false, nil))
	for _, p := range []Phase{{}, {Number: 2, Total: 1}, {Number: -1, Total: 2}, {Number: 0, Total: 0}} {
		if err := r.Update(&p); err == nil {
			t.Fatal("accepted invalid counters")
		}
	}
	if err := r.Success(&Summary{Layers: -1}); err == nil {
		t.Fatal("accepted negative layer count")
	}
	if err := r.Success(&Summary{UncompressedBytes: -1}); err == nil {
		t.Fatal("accepted negative size")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal(out.String())
	}
}

// TestReporter_SuccessOmitsAnEmptyDestination keeps the closing line honest: a build
// that wrote nowhere has no destination, and printing "destination=" afterwards reads as
// a truncated line rather than a deliberate absence.
func TestReporter_SuccessOmitsAnEmptyDestination(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	r := New(t.Context(), testConfig(&out, false, nil))
	if err := r.Success(&Summary{Target: "build", Image: "demo:v1",
		Platforms: []string{"linux/amd64"}, Layers: 1, UncompressedBytes: 1 << 20,
		Attestations: []string{"sbom"}}); err != nil {
		t.Fatal(err)
	}
	want := "success: target=build image=demo:v1 platforms=linux/amd64 layers=1 uncompressed=1.0 MiB attestations=sbom\n"
	if got := out.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestReporter_RedrawsWithoutRepeatingAStep covers a step whose details arrive in a
// second call: the plain renderer must not print it twice, because a log reader cannot
// tell the two lines apart from a step that really ran twice.
func TestReporter_RedrawsWithoutRepeatingAStep(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	r := New(t.Context(), testConfig(&out, false, nil))
	if err := r.Update(&Phase{Target: "build", Number: 3, Total: 5, Title: "render"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Update(&Phase{Target: "build", Number: 3, Total: 5, Title: "render", Details: "2 statements"}); err != nil {
		t.Fatal(err)
	}
	if err := r.CompletePhase(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	want := "running [build] [3/5] render\n✓ [build] [3/5] render — 2 statements\n"
	if got := out.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A bar appears only for a run whose size is known, since a bar without a total would
// be a decoration that lies about progress.
func TestReporter_DrawsABarOnlyForASizedRun(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	r := New(t.Context(), testConfig(&out, true, nil))
	if err := r.Update(&Phase{Target: "build", Number: 4, Total: 5, Title: "write tarball"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Stream("", 40, 100); err != nil {
		t.Fatal(err)
	}
	want := "██████░░░░░░░░░ 40% 40 B/100 B"
	if got := r.active.Done; got != 40 {
		t.Fatalf("Done = %d", got)
	}
	line := r.stepTextLocked()
	if !strings.Contains(line, want) {
		t.Fatalf("step line %q does not contain %q", line, want)
	}
	if err := r.Stream("", 0, 0); err != nil {
		t.Fatal(err)
	}
	// A run with no total keeps the last measurement rather than clearing the bar.
	if !strings.Contains(r.stepTextLocked(), want) {
		t.Fatalf("a stream without a total cleared the bar: %q", r.stepTextLocked())
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
}

// A streamed item names what is being worked on and never prints a second line for the
// same step, which is what keeps a forty-package image to one line.
func TestReporter_StreamsWithoutRepeatingAStep(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	r := New(t.Context(), testConfig(&out, false, nil))
	if err := r.Update(&Phase{Target: "lock", Number: 1, Total: 3, Title: "collect inputs"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"libc6 2.39", "libssl3t64 3.0.13", "openssl 3.0.13"} {
		if err := r.Stream(name, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.CompletePhase(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	// A pipe cannot redraw, so the first item appears as its own line and the step's
	// completion stays a separate record.
	want := "running [lock] [1/3] collect inputs\n" +
		"running [lock] [1/3] collect inputs: libc6 2.39\n" +
		"\u2713 [lock] [1/3] collect inputs\n"
	if got := out.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Quiet keeps the step record and drops the item names, for a caller that wants a log
// of what happened rather than a trail of what was downloaded.
func TestReporter_QuietDropsItemNames(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	cfg := testConfig(&out, true, nil)
	cfg.Quiet = true
	r := New(t.Context(), cfg)
	if err := r.Update(&Phase{Target: "lock", Number: 1, Total: 3, Title: "collect inputs"}); err != nil {
		t.Fatal(err)
	}
	for i := range streamEvery * 2 {
		if err := r.Stream(fmt.Sprintf("pkg%d 1.0", i), int64(i), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.CompletePhase(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "pkg") {
		t.Fatalf("quiet output named an item:\n%s", out.String())
	}
	want := "running [lock] [1/3] collect inputs\n✓ [lock] [1/3] collect inputs\n"
	if got := out.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A plain reporter cannot redraw, so it prints an item every streamEvery rather than
// one per archive, which is what keeps a large image readable in a log.
func TestReporter_PlainStreamsPeriodically(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	r := New(t.Context(), testConfig(&out, false, nil))
	if err := r.Update(&Phase{Target: "lock", Number: 1, Total: 3, Title: "collect inputs"}); err != nil {
		t.Fatal(err)
	}
	for i := range streamEvery * 3 {
		if err := r.Stream(fmt.Sprintf("pkg%02d 1.0", i), int64(i), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.CompletePhase(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	// The first item always prints, then one every streamEvery.
	if got := strings.Count(out.String(), ": pkg"); got != 4 {
		t.Fatalf("streamed %d item lines over %d items, want 4:\n%s", got, streamEvery*3, out.String())
	}
	for _, named := range []string{"pkg00 1.0", "pkg19 1.0", "pkg59 1.0"} {
		if !strings.Contains(out.String(), named) {
			t.Fatalf("%q was not streamed:\n%s", named, out.String())
		}
	}
}
