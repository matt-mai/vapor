package builder

import "sync"

// Progress is told what a build is working on, so a command can name it. Steps arrive
// from the goroutines that assemble platforms, so an implementation must be safe for
// concurrent use.
type Progress func(Step)

// Step is one thing a build is working on. Name says what a person should read: the
// archive being unpacked, or a stage such as "compress layer". Done and Total measure
// the locked bytes every platform has unpacked so far, so the measurement only grows
// while platforms build concurrently. A stage that reads no archive carries the last
// measurement instead of inventing one.
type Step struct {
	Name  string
	Done  int64
	Total int64
}

// stepCounts accumulates what the platforms unpacked. Every platform adds its locked
// archive bytes to one total, so a concurrent build still shows one moving number.
type stepCounts struct {
	mu    sync.Mutex
	total int64
	known bool
	done  int64
}

// extract announces the archive about to be unpacked and counts it as reached, so the
// measured line never stalls an archive short while the last one is still open.
func (i *Input) extract(name string, size int64) {
	if i.progress == nil {
		return
	}
	i.counts.mu.Lock()
	if !i.counts.known {
		i.counts.total, i.counts.known = i.payloadBytes(), true
	}
	i.counts.done += size
	done, total := i.counts.done, i.counts.total
	i.counts.mu.Unlock()
	i.progress(Step{Name: name, Done: done, Total: total})
}

// working announces a stage that reads no archive, such as hardening. It repeats the
// last measurement so a bar already on screen keeps its place.
func (i *Input) working(name string) {
	if i.progress == nil {
		return
	}
	i.counts.mu.Lock()
	done, total := i.counts.done, i.counts.total
	i.counts.mu.Unlock()
	i.progress(Step{Name: name, Done: done, Total: total})
}

// payloadBytes is how many bytes of locked archives the build unpacks: whole packages,
// slice packages and artifacts, for every platform. It is the size of the extraction
// work, which is what the measurement counts.
func (i *Input) payloadBytes() int64 {
	var size int64
	for index := range i.lockfile.Packages {
		size += i.lockfile.Packages[index].Content.Size
	}
	for index := range i.lockfile.Slices {
		size += i.lockfile.Slices[index].Content.Size
	}
	for index := range i.lockfile.Artifacts {
		size += i.lockfile.Artifacts[index].Size
	}
	return size
}
