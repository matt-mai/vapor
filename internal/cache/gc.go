package cache

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// stagingPrefix marks the temporary files Store publishes blobs from.
const stagingPrefix = ".vapor-blob-"

// GCOptions tunes one collection run.
type GCOptions struct {
	// Now is the reference time for MinAge; zero means time.Now.
	Now time.Time
	// MinAge protects anything younger than this: a blob a concurrent lock is about to
	// reference, and a staging file a concurrent Store is still writing.
	MinAge time.Duration
	// Apply deletes. Without it the run only reports what it would remove.
	Apply bool
}

// GCStats reports what one collection run found.
type GCStats struct {
	Kept         int
	Removed      int
	RemovedBytes int64
	Skipped      int
	TooNew       int
	// InFlight names staging files a running Store still owns. Any entry means the
	// cache is in use and Apply refuses.
	InFlight []string
}

// GC removes every blob that is not in keep and no staging file that is too young to
// be a leftover.
func (c *Cache) GC(keep map[string]struct{}, options GCOptions) (GCStats, error) {
	if c == nil || c.dir == "" {
		return GCStats{}, errors.New("cache is not initialized")
	}
	if options.MinAge < 0 {
		return GCStats{}, fmt.Errorf("minimum age %s must not be negative", options.MinAge)
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	stats, paths, err := c.collect(keep, now, options.MinAge)
	if err != nil {
		return GCStats{}, err
	}
	if len(stats.InFlight) != 0 && options.Apply {
		return GCStats{}, fmt.Errorf("cache write in progress (%s); retry when it finishes", stats.InFlight[0])
	}
	if !options.Apply {
		return stats, nil
	}
	if err := removeAll(paths); err != nil {
		return GCStats{}, err
	}
	return stats, nil
}

// collect walks the cache once and reports what a sweep would remove.
func (c *Cache) collect(keep map[string]struct{}, now time.Time, minAge time.Duration) (GCStats, []string, error) {
	shards, err := os.ReadDir(filepath.Join(c.dir, "sha256"))
	if err != nil {
		return GCStats{}, nil, fmt.Errorf("read cache directory: %w", err)
	}
	var stats GCStats
	var doomed []string
	for _, shard := range shards {
		entries, err := c.collectShard(shard, keep, now, minAge, &stats, &doomed)
		if err != nil {
			return GCStats{}, nil, err
		}
		if entries == 0 && isRemovableShard(shard) && len(doomed) != 0 {
			doomed = append(doomed, filepath.Join(c.dir, "sha256", shard.Name()))
		}
	}
	return stats, doomed, nil
}

// collectShard reports one shard's blobs and counts the entries it keeps. It returns the
// number of entries left, so an emptied directory can be removed.
func (c *Cache) collectShard(shard fs.DirEntry, keep map[string]struct{}, now time.Time,
	minAge time.Duration, stats *GCStats, doomed *[]string,
) (int, error) {
	path := filepath.Join(c.dir, "sha256", shard.Name())
	if !shard.IsDir() {
		stats.Skipped++
		return 1, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, fmt.Errorf("read cache shard: %w", err)
	}
	left := 0
	for _, entry := range entries {
		removable, err := c.collectEntry(path, shard.Name(), entry, keep, now, minAge, stats)
		if err != nil {
			return 0, err
		}
		if removable != "" {
			*doomed = append(*doomed, removable)
			continue
		}
		left++
	}
	return left, nil
}

// collectEntry decides what happens to one shard entry and names the path to delete, if
// the entry is doomed. It returns "" for anything that stays.
func (c *Cache) collectEntry(dir, shard string, entry fs.DirEntry, keep map[string]struct{}, now time.Time,
	minAge time.Duration, stats *GCStats,
) (string, error) {
	name := entry.Name()
	path := filepath.Join(dir, name)
	if entry.IsDir() {
		stats.Skipped++
		return "", nil
	}
	fresh, err := freshFile(entry, now, minAge)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(name, stagingPrefix) {
		if fresh {
			stats.TooNew++
			stats.InFlight = append(stats.InFlight, name)
			return "", nil
		}
		stats.Removed++
		return path, nil
	}
	if digest, decoded := isDerived(name); decoded {
		return collectDerived(path, digest, keep, fresh, stats), nil
	}
	if !validDigest(name) || name[:2] != shard {
		stats.Skipped++
		return "", nil
	}
	if _, ok := keep[name]; ok {
		stats.Kept++
		return "", nil
	}
	if entry.Type()&fs.ModeSymlink != 0 {
		stats.Skipped++
		return "", nil
	}
	if fresh {
		stats.TooNew++
		return "", nil
	}
	info, err := entry.Info()
	if err != nil {
		return "", fmt.Errorf("stat cache blob: %w", err)
	}
	stats.Removed++
	stats.RemovedBytes += info.Size()
	return path, nil
}

// collectDerived decides a decoded entry by the blob it came from, which is the same
// answer the blob itself gets: a memo of a kept blob is kept, and one of a removed blob
// is removed with it.
func collectDerived(path, digest string, keep map[string]struct{}, fresh bool, stats *GCStats) string {
	if _, ok := keep[digest]; ok {
		stats.Kept++
		return ""
	}
	if fresh {
		stats.TooNew++
		return ""
	}
	stats.Removed++
	return path
}

// freshFile reports whether an entry is young enough to belong to a running command.
func freshFile(entry fs.DirEntry, now time.Time, minAge time.Duration) (bool, error) {
	info, err := entry.Info()
	if err != nil {
		return false, fmt.Errorf("stat cache entry: %w", err)
	}
	return now.Sub(info.ModTime()) < minAge, nil
}

func isRemovableShard(shard fs.DirEntry) bool {
	return shard.IsDir() && len(shard.Name()) == 2
}

// removeAll deletes the doomed paths and reports every failure, so a partial sweep is
// never silent.
func removeAll(paths []string) error {
	var failures []error
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove %s: %w", filepath.Base(path), err))
		}
	}
	return errors.Join(failures...)
}

// Clean empties the cache. Unlike GC it keeps nothing and asks no questions: the caller
// was explicit about wanting an empty cache.
func (c *Cache) Clean() error {
	if c == nil || c.dir == "" {
		return errors.New("cache is not initialized")
	}
	root := filepath.Join(c.dir, "sha256")
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove cache directory: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	return nil
}
