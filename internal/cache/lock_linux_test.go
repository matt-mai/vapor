package cache_test

import (
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/cache"
)

func TestLockGC_SharesReadersAndExcludesGC(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := openGuardStore(t, dir)
	second := openGuardStore(t, dir)
	releaseFirst := acquireGuard(t, first, false)
	releaseSecond := acquireGuard(t, second, false)
	assertGuardBusy(t, second, true)
	releaseFirst()
	assertGuardBusy(t, first, true)
	releaseSecond()
	acquireGuard(t, first, true)
	assertGuardBusy(t, second, false)
	acquireGuard(t, openGuardStore(t, t.TempDir()), true)
}

func openGuardStore(t *testing.T, dir string) *cache.Cache {
	t.Helper()
	store, err := cache.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func acquireGuard(t *testing.T, store *cache.Cache, exclusive bool) func() {
	t.Helper()
	release, err := store.LockGC(exclusive)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	return release
}

func assertGuardBusy(t *testing.T, store *cache.Cache, exclusive bool) {
	t.Helper()
	release, err := store.LockGC(exclusive)
	if err == nil {
		release()
		t.Fatal("acquired a conflicting cache guard")
	}
	if !strings.Contains(err.Error(), "cache is busy; retry") {
		t.Fatal(err)
	}
}
