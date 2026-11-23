package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/matt-mai/vapor/internal/builder"
	"github.com/matt-mai/vapor/internal/ui"
)

// newReporterConfig says where progress goes and whether a person is watching. The
// spinner is worth drawing only for a terminal: a log file or a pipe wants one line per
// step, because carriage returns and cursor moves would arrive as noise. The two flags
// turn it down further: --no-progress keeps one line per step with no animation, and
// --quiet also stops naming the item being collected.
func newReporterConfig(cmd *cobra.Command) *ui.Config {
	out := cmd.ErrOrStderr()
	flags := cmd.Flags()
	plain, err := flags.GetBool("no-progress")
	if err != nil {
		plain = false
	}
	quiet, err := flags.GetBool("quiet")
	if err != nil {
		quiet = false
	}
	return &ui.Config{Stderr: out, Plain: plain, Quiet: quiet, Terminal: func() bool {
		return ui.IsTerminal(underlyingFile(out))
	}}
}

// streamAssembly names what assembly is unpacking on the step line, with a bar over
// the locked archive bytes a build reads. Bytes are what the lock knows before the
// work starts, so the measurement is honest from the first archive; each archive
// counts as reached when extraction begins, which reaches the total on the last one.
func streamAssembly(reporter *ui.Reporter) builder.Progress {
	return func(step builder.Step) {
		// A closed reporter, a canceled context or a full disk ends the run on its own;
		// failing assembly here would hide the real cause behind a display error.
		_ = reporter.Stream(step.Name, step.Done, step.Total)
	}
}

// underlyingFile finds the file behind the writers that wrap standard error, so a
// wrapper added for error bookkeeping does not hide the terminal underneath it.
func underlyingFile(writer io.Writer) *os.File {
	for range 8 {
		file, ok := writer.(*os.File)
		if ok {
			return file
		}
		switch wrapped := writer.(type) {
		case *outputWriter:
			writer = wrapped.Writer
		case interface{ Unwrap() io.Writer }:
			writer = wrapped.Unwrap()
		case interface{ Unwrap() error }:
			cause := wrapped.Unwrap()
			next, more := cause.(io.Writer)
			if !more {
				return nil
			}
			writer = next
		default:
			return nil
		}
	}
	return nil
}
