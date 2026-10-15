package api

import (
	"hash/maphash"
	"sync"
	"time"
)

// responseCache keeps rendered responses for the read-mostly endpoints for a few
// seconds. It is split into shards so dashboard polling does not serialise on one
// lock.
type responseCache struct {
	seed   maphash.Seed
	ttl    time.Duration
	shards [16]cacheShard
}

type cacheShard struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	body    []byte
	expires time.Time
}

func newResponseCache(ttl time.Duration) *responseCache {
	c := &responseCache{seed: maphash.MakeSeed(), ttl: ttl}
	for i := range c.shards {
		c.shards[i].entries = make(map[string]cacheEntry)
	}
	return c
}

func (c *responseCache) shard(key string) *cacheShard {
	return &c.shards[maphash.String(c.seed, key)%uint64(len(c.shards))]
}

// get returns a cached body, or calls render and caches what it returns.
func (c *responseCache) get(key string, now time.Time, render func() ([]byte, error)) ([]byte, error) {
	s := c.shard(key)
	s.mu.Lock()
	e, ok := s.entries[key]
	s.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.body, nil
	}
	body, err := render()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.entries[key] = cacheEntry{body: body, expires: now.Add(c.ttl)}
	s.mu.Unlock()
	return body, nil
}

// drop forgets a key after a write that changes it.
func (c *responseCache) drop(key string) {
	s := c.shard(key)
	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()
}
