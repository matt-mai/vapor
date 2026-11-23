// Package ui renders progress diagnostics independently of build inputs and outputs.
package ui

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// ErrStopped indicates an event arrived after shutdown.
var ErrStopped = errors.New("progress reporter stopped")

// Config supplies presentation dependencies. Stderr defaults to os.Stderr.
// Terminal must positively identify Stderr as a terminal; nil selects plain output.
// Secrets must include any credentials that could occur outside URL components.
// Plain suppresses the animated line and the bars, for a caller who only wants the
// phase record. Quiet does the same and also stops naming the item being worked on.
// Now and Ticks are optional test controls; a supplied tick channel is caller-owned.
type Config struct {
	Stderr   io.Writer
	Terminal func() bool
	Getenv   func(string) string
	Secrets  []string
	Plain    bool
	Quiet    bool
	Now      func() time.Time
	Ticks    <-chan time.Time
}

// Phase describes the target being built and its numbered step. Details contain the
// result so far, Item names what is being worked on, and Done/Max measure a run whose
// size is known; a bar is drawn only when Max is positive.
type Phase struct {
	Target  string
	Number  int
	Total   int
	Title   string
	Details string
	Item    string
	Done    int64
	Max     int64
}

// Reporter serializes all output. The mutex protects state and writes; channels
// only signal shutdown and join the context/spinner worker.
type Reporter struct {
	mu              sync.Mutex
	ctx             context.Context
	out             io.Writer
	now             func() time.Time
	secrets         []string
	animated, color bool
	// streaming says whether a phase may name the item being worked on. It is separate
	// from animated because a piped log still gets one line per step, where the item
	// name is worth having, while a spinner or bar needs a terminal.
	streaming bool
	// streamed counts the items named so far, so a reporter that cannot redraw a line
	// prints one every streamEvery instead of one per item.
	streamed int
	active   *Phase
	started  time.Time
	frame    int
	stopped  bool
	err      error
	stop     chan struct{}
	done     chan struct{}
}

// New starts a reporter. The owner must call Stop, Fail or Success, even when the
// context is canceled, to join the worker and collect output errors.
func New(ctx context.Context, cfg *Config) *Reporter {
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	animated := !cfg.Plain && !cfg.Quiet && cfg.Terminal != nil && cfg.Terminal() && cfg.Getenv("CI") == "" &&
		cfg.Getenv("TERM") != "dumb"
	r := &Reporter{ctx: ctx, out: cfg.Stderr, now: cfg.Now, secrets: append([]string(nil), cfg.Secrets...),
		animated: animated, color: animated && cfg.Getenv("NO_COLOR") == "", streaming: !cfg.Quiet,
		stop: make(chan struct{}), done: make(chan struct{})}
	go r.run(ctx, cfg.Ticks)
	return r
}

func (r *Reporter) run(ctx context.Context, ticks <-chan time.Time) {
	defer close(r.done)
	if r.animated && ticks == nil {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		select {
		case <-r.stop:
			return
		case <-ctx.Done():
			r.mu.Lock()
			r.cancelLocked()
			r.mu.Unlock()
			return
		case _, ok := <-ticks:
			if !ok {
				ticks = nil
				continue
			}
			r.mu.Lock()
			if r.eventErrorLocked() == nil && r.animated && r.active != nil {
				r.frame++
				r.renderLocked()
			}
			r.mu.Unlock()
		}
	}
}

func (r *Reporter) shutdownLocked(err error) {
	if err != nil && r.err == nil {
		r.err = err
	}
	if !r.stopped {
		r.stopped = true
		close(r.stop)
	}
}

func (r *Reporter) cancelLocked() {
	if !r.stopped && r.ctx.Err() != nil {
		r.lineLocked("canceled", "operation canceled")
		r.shutdownLocked(r.ctx.Err())
	}
}

func (r *Reporter) eventErrorLocked() error {
	r.cancelLocked()
	if r.err != nil {
		return r.err
	}
	if r.stopped {
		return ErrStopped
	}
	return nil
}

// Stop preserves the current phase as stopped, joins the worker and returns the
// first output/cancellation error. Repeated calls return the same result.
func (r *Reporter) Stop() error {
	r.mu.Lock()
	r.cancelLocked()
	if !r.stopped {
		if r.active != nil {
			r.lineLocked("stopped", "")
		}
		r.shutdownLocked(nil)
	}
	r.mu.Unlock()
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
