package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRun_DispatchAndErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{name: "missing command", code: 2, want: "a command is required"},
		{name: "help command", args: []string{"help"}, want: "Usage:"},
		{name: "long help", args: []string{"--help"}, want: "Usage:"},
		{name: "short help", args: []string{"-h"}, want: "Usage:"},
		{name: "named help", args: []string{"help", "build"}, want: "vaporize build"},
		{name: "help before positional validation", args: []string{"build", "extra", "--help"}, want: "vaporize build"},
		{name: "unknown help topic", args: []string{"help", "unknown"}, code: 2, want: `unknown help command "unknown"`},
		{name: "unknown command", args: []string{"unknown"}, code: 2, want: `unknown command "unknown"`},
		{name: "unknown global flag", args: []string{"--unknown"}, code: 2, want: "unknown flag: --unknown"},
		{name: "extra help argument", args: []string{"help", "build", "extra"}, code: 2, want: "accepts at most 1 arg"},
		{name: "extra flag after global help", args: []string{"--help", "--unknown"}, code: 2, want: "unknown flag: --unknown"},
		{name: "extra command argument", args: []string{"vex", "a.yaml", "b.yaml"}, code: 2, want: "accepts at most 1 arg"},
		{name: "named help for vex", args: []string{"help", "vex"}, want: "vaporize vex"},
		{name: "unknown command flag", args: []string{"build", "--unknown"}, code: 2, want: "unknown flag: --unknown"},
		{name: "extra flag after command help", args: []string{"build", "--help", "--unknown"}, code: 2, want: "unknown flag: --unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.code {
				t.Fatalf("exit code = %d, want %d", code, tt.code)
			}
			output, empty := &stdout, &stderr
			if tt.code != 0 {
				output, empty = &stderr, &stdout
			}
			if !strings.Contains(output.String(), tt.want) || empty.Len() != 0 {
				t.Fatalf("stdout = %q, stderr = %q; want %q on only the expected stream", &stdout, &stderr, tt.want)
			}
		})
	}
}

func TestRun_VersionReportsTheStampedVersion(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got == "" {
		t.Fatal("version printed nothing")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}

func TestRun_OutputFailure(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--help"}, {"build", "--help"}, {"build"}, {"unknown"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if code := run(args, failingWriter{}, failingWriter{}); code != 1 {
				t.Fatalf("exit code = %d, want 1 for output failure", code)
			}
		})
	}
}
