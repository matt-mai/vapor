//go:build !linux

package cache

import "errors"

func (c *Cache) LockGC(_ bool) (func(), error) {
	return nil, errors.New("cache GC coordination requires Linux")
}
