package main

import (
	"os"

	"github.com/matt-mai/vapor/internal/mutation"
)

func main() {
	// A process re-executed as a mutation sandbox worker must not parse arguments:
	// it reads one request from stdin and exits with the script's outcome.
	if mutation.WorkerRequested() {
		os.Exit(mutation.RunWorker(os.Stdin, os.Stdout))
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
