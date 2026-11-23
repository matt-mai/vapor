package builder

import (
	"context"
	"sync"

	"github.com/matt-mai/vapor/internal/oci"
)

// BuildEach assembles the declared platforms with at most jobs builds running at
// once, calling done as each image finishes so a caller can report progress while
// the remaining platforms are still building. done is called from a single
// goroutine, in completion order. The worker count is capped at the platform count.
// A jobs value below one requests one worker.
//
// The returned images are in declaration order. A failure cancels the remaining
// builds and returns the failure itself: a platform stopped by a sibling's failure
// reports a cancellation, which says nothing about what went wrong, so it is never
// the error a caller sees. An error from done cancels the builds as well.
func (i *Input) BuildEach(ctx context.Context, level oci.CompressionLevel, jobs int,
	done func(oci.Platform) error,
) ([]Image, error) {
	platforms, err := i.Platforms()
	if err != nil {
		return nil, err
	}
	built, err := i.buildConcurrently(ctx, platforms, level, jobs, done)
	if err != nil {
		return nil, err
	}
	images := make([]Image, 0, len(platforms))
	for index := range built {
		images = append(images, built[index].image)
	}
	return images, nil
}

// builtImage is one platform's outcome. Orphans write their own slot and stop, so a
// slot is written at most once and is read only after the coordinator returned.
type builtImage struct {
	image Image
	err   error
}

// buildConcurrently runs the platforms and returns one outcome per platform, in
// declaration order. Each finished platform is handed to the collector, which is the
// only caller of done; a failed build abandons the platforms still queued, so their
// slots stay zero.
func (i *Input) buildConcurrently(ctx context.Context, platforms []oci.Platform,
	level oci.CompressionLevel, jobs int, done func(oci.Platform) error,
) ([]builtImage, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	finished := make(chan outcome)
	work := make(chan int)
	group := &sync.WaitGroup{}
	for range buildWorkerCount(jobs, len(platforms)) {
		group.Go(func() {
			for index := range work {
				if ctx.Err() == nil {
					i.workPlatform(ctx, platforms, index, level, finished, cancel)
				}
			}
		})
	}
	queued := queueWork(ctx, work, len(platforms))
	go func() {
		group.Wait()
		close(finished)
	}()
	built, failure := collect(len(platforms), platforms, finished, done, cancel)
	<-queued
	return built, failure
}

// queueWork feeds the platform indexes to the workers and returns a channel closed
// once nothing more can be queued. Canceling stops it, so a failed build does not
// start the platforms still waiting.
func queueWork(ctx context.Context, work chan<- int, count int) <-chan struct{} {
	queued := make(chan struct{})
	go func() {
		defer close(work)
		defer close(queued)
		for index := range count {
			select {
			case work <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	return queued
}

// workPlatform builds one platform and reports it. It waits until the collector has
// the result, because the collector may have canceled the build for an earlier
// failure and this worker must not take another platform after that.
func (i *Input) workPlatform(ctx context.Context, platforms []oci.Platform, index int,
	level oci.CompressionLevel, finished chan<- outcome, cancel context.CancelCauseFunc,
) {
	image, err := i.BuildPlatform(ctx, platforms[index], level)
	settled := make(chan struct{})
	finished <- outcome{index: index, image: image, err: err, settled: settled}
	<-settled
	if err != nil {
		cancel(err)
	}
}

// collect drains finished until the workers are done. It calls done in completion
// order and stops reporting once anything has failed, which also stops the builds.
func collect(count int, platforms []oci.Platform, finished <-chan outcome,
	done func(oci.Platform) error, cancel context.CancelCauseFunc,
) ([]builtImage, error) {
	built := make([]builtImage, count)
	var failure error
	for result := range finished {
		built[result.index] = builtImage{image: result.image, err: result.err}
		if failure == nil {
			if result.err != nil {
				failure = result.err
				cancel(result.err)
			} else if err := done(platforms[result.index]); err != nil {
				failure = err
				cancel(err)
			}
		}
		close(result.settled)
	}
	return built, failure
}

// outcome is one finished platform waiting to be collected.
type outcome struct {
	index   int
	image   Image
	err     error
	settled chan struct{}
}

func buildWorkerCount(jobs, platforms int) int {
	return min(max(jobs, 1), platforms)
}
