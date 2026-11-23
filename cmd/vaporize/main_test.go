package main

import (
	"os"
	"testing"

	"github.com/matt-mai/vapor/internal/mutation"
)

// TestMain turns the test binary into a sandbox worker when a build re-executes it, so
// a slice mutation crosses the real process boundary rather than a stub.
func TestMain(m *testing.M) {
	if mutation.WorkerRequested() {
		os.Exit(mutation.RunWorker(os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}
