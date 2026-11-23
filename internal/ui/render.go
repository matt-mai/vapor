package ui

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// outputError retains the writer cause without displaying potentially secret text.
type outputError struct{ cause error }

func (e *outputError) Error() string { return "write progress: output failed" }
func (e *outputError) Unwrap() error { return e.cause }

func (r *Reporter) writeLocked(text string) {
	if r.err != nil {
		return
	}
	n, err := io.WriteString(r.out, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	if err != nil {
		r.shutdownLocked(&outputError{cause: err})
	}
}

func (r *Reporter) phaseTextLocked() string {
	if r.active == nil {
		return ""
	}
	p := r.active
	text := fmt.Sprintf("[%s] [%d/%d] %s", r.clean(p.Target), p.Number, p.Total, r.clean(p.Title))
	if p.Details != "" {
		text += " — " + r.clean(p.Details)
	}
	return text
}

// renderLocked draws the animated line that replaces itself. A person reading along
// does not need the target repeated beside every step, so only the step, its detail and
// the elapsed time are animated; the numbering stays because it says how much is left.
func (r *Reporter) renderLocked() {
	frames := [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	text := frames[r.frame%len(frames)] + " " + r.stepTextLocked()
	text += " " + max(time.Duration(0), r.now().Sub(r.started)).Truncate(time.Second).String()
	if r.color {
		text = "\x1b[36m" + text + "\x1b[0m"
	}
	r.writeLocked("\r\x1b[2K" + text)
}

// stepTextLocked is the animated form of the active phase: the step alone, since the
// target is the same on every line of a build. What is being worked on follows the
// step, because a person reading along wants to know what the current one is, not
// which image it belongs to. A run whose size is known grows a bar; everything else
// keeps the spinner, which honestly says "working" without inventing a percentage.
func (r *Reporter) stepTextLocked() string {
	p := r.active
	if p == nil {
		return ""
	}
	text := fmt.Sprintf("[%d/%d] %s", p.Number, p.Total, r.clean(p.Title))
	if p.Details != "" {
		text += " — " + r.clean(p.Details)
	}
	if r.streaming {
		if p.Item != "" {
			text += " — " + r.clean(p.Item)
		}
	}
	if p.Max > 0 {
		text += " " + barLocked(p.Done, p.Max) + " " + measureLocked(p.Done, p.Max)
	}
	return text
}

// barWidth is how many cells the bar occupies. A progress line also carries the step,
// the item and the elapsed time, so the bar stays narrow enough to fit an 80-column
// terminal without wrapping.
const barWidth = 15

// barLocked draws the completed fraction as filled and empty cells.
func barLocked(done, total int64) string {
	filled := 0
	if total > 0 {
		filled = int(min(total, atLeastZero(done)) * barWidth / total)
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
}

// measureLocked reports how far through a sized run the phase is, as a percentage and
// as the bytes covered. It is the number a person can act on: 52% says how long is
// left, 21.4/40.7 MiB says how much work the number stands for.
func measureLocked(done, total int64) string {
	if total <= 0 {
		return ""
	}
	done = min(total, atLeastZero(done))
	percent := done * 100 / total
	return fmt.Sprintf("%d%% %s/%s", percent, HumanBytes(done), HumanBytes(total))
}

// atLeastZero floors a measurement at zero, so a count that went backwards cannot draw
// a negative bar or a negative byte total.
func atLeastZero(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func (r *Reporter) lineLocked(status, message string) {
	text := status
	if phase := r.phaseTextLocked(); phase != "" {
		text += " " + phase
	}
	if message != "" {
		text += ": " + r.clean(message)
	}
	if r.animated {
		text = "\r\x1b[2K" + text
	}
	r.writeLocked(text + "\n")
}

// Stream names what the active phase is working on. A phase whose size is known passes
// its measured progress, so the line grows a bar; one that is not known passes a max of
// zero and keeps the count out of the line rather than inventing a total. An update for
// the same step never prints a second line, so a caller can stream freely.
//
// When the reporter cannot redraw a line — a pipe, --no-progress — the item is printed
// on its own line every streamEvery items, so a log still shows what was collected
// without one line per archive.
func (r *Reporter) Stream(item string, done, total int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.eventErrorLocked(); err != nil {
		return err
	}
	if r.active == nil {
		return r.err
	}
	if r.streaming {
		r.active.Item = item
	}
	if total > 0 {
		r.active.Done, r.active.Max = done, total
	}
	if r.animated {
		r.renderLocked()
		return r.err
	}
	if r.streaming && item != "" {
		r.streamed++
		// The first item is always worth a line: a small image collects fewer archives
		// than streamEvery, and a run that showed nothing reads as a run that did nothing.
		if r.streamed == 1 || r.streamed%streamEvery == 0 {
			r.lineLocked("running", item)
		}
	}
	return r.err
}

// streamEvery is how many collected items a plain reporter waits between lines. Twenty
// keeps a two-hundred-package image to a dozen lines while still showing movement.
const streamEvery = 20

// Update starts or replaces the active phase. CompletePhase should precede a
// different phase so its completed record remains visible.
func (r *Reporter) Update(p *Phase) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.eventErrorLocked(); err != nil {
		return err
	}
	if p.Number < 1 || p.Total < p.Number {
		return fmt.Errorf("update progress: invalid phase counters")
	}
	// A step whose details arrive in a second call is the same step: replacing the
	// active phase must not print it twice, and in a terminal it simply redraws.
	sameStep := r.active != nil && r.active.Target == p.Target && r.active.Number == p.Number
	if !sameStep {
		r.started = r.now()
	}
	r.active = p
	if r.animated {
		r.renderLocked()
	} else if !sameStep {
		r.lineLocked("running", "")
	}
	return r.err
}

// CompletePhase leaves a permanent completion line and clears the active phase.
func (r *Reporter) CompletePhase() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.eventErrorLocked(); err != nil {
		return err
	}
	if r.active != nil {
		r.lineLocked("✓", "")
		r.active = nil
	}
	return r.err
}

// Warning writes a non-fatal diagnostic.
func (r *Reporter) Warning(message string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.eventErrorLocked(); err != nil {
		return err
	}
	r.lineLocked("warning", message)
	if r.animated && r.active != nil && !r.stopped {
		r.renderLocked()
	}
	return r.err
}

// Failure carries a safe outer message and optional known, actionable guidance.
// Do not pass raw library errors or invent remedies from error-string matching.
type Failure struct {
	Message  string
	Guidance string
}

// Fail writes a failure record with the active phase, then stops and joins.
// Its return value is the reporting error, not the operation's failure.
func (r *Reporter) Fail(f Failure) error {
	message := f.Message
	if f.Guidance != "" {
		message += "; " + f.Guidance
	}
	return r.finish("failed", message)
}

// Summary contains actual completed outputs, never planned outputs.
type Summary struct {
	Target            string
	Image             string
	Platforms         []string
	Layers            int
	UncompressedBytes int64
	Attestations      []string
	Destination       string
}

// Success reports completed outputs, then stops and joins. Call it only after
// all required outputs and checks succeed.
func (r *Reporter) Success(s *Summary) error {
	if s.Layers < 0 || s.UncompressedBytes < 0 {
		return errors.Join(fmt.Errorf("summarize progress: negative output count"), r.Stop())
	}
	fields := []string{
		"target=" + s.Target,
		"image=" + s.Image,
		"platforms=" + strings.Join(s.Platforms, ","),
		fmt.Sprintf("layers=%d", s.Layers),
		"uncompressed=" + HumanBytes(s.UncompressedBytes),
		"attestations=" + strings.Join(s.Attestations, ","),
	}
	// A build that writes nowhere has no destination; an empty field reads as a bug.
	if s.Destination != "" {
		fields = append(fields, "destination="+s.Destination)
	}
	return r.finish("success", strings.Join(fields, " "))
}

func (r *Reporter) finish(status, message string) error {
	r.mu.Lock()
	r.cancelLocked()
	if !r.stopped {
		r.lineLocked(status, message)
		r.active = nil
		r.shutdownLocked(nil)
	}
	r.mu.Unlock()
	return r.Stop()
}
