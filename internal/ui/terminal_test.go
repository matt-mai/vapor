package ui

import (
	"os"
	"testing"
)

func TestIsTerminalRejectsWhatIsNotAFile(t *testing.T) {
	t.Parallel()
	if IsTerminal(nil) {
		t.Fatal("nil file reported as a terminal")
	}
}

// TestIsTerminalRejectsARegularFile covers the case that matters for logs: a redirected
// standard error must render one line per step, never cursor movements.
func TestIsTerminalRejectsARegularFile(t *testing.T) {
	t.Parallel()
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if IsTerminal(file) {
		t.Fatal("a regular file reported as a terminal")
	}
}
