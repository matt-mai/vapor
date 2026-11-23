//go:build race

package mutation_test

// raceMemoryFactor scales the memory bound for tests built with the race detector,
// whose instrumentation needs far more heap than the worker's default bound allows.
const raceMemoryFactor = 64
