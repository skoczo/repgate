package cache

import (
	"sync"
	"time"
)

type IPRecord struct {
	IP        string
	Status    string
	Score     int
	Source    string
	CheckedAt time.Time
	ExpiresAt time.Time
}

type IPCache struct {
	mu      sync.RWMutex
	cache   map[string]IPRecord
	maxSize int
}

func NewIPCache(maxSize int) *IPCache {
	return &IPCache{cache: make(map[string]IPRecord), maxSize: maxSize}
}

func (c *IPCache) Get(ip string) (IPRecord, bool) {
	c.mu.RLock()
	record, ok := c.cache[ip]
	c.mu.RUnlock()
	return record, ok
}

func (c *IPCache) Set(ip string, record IPRecord) {
	c.mu.Lock()
	if len(c.cache) >= c.maxSize {
		// remove 10% of the oldest records
		for oldestKey := range c.cache {
			if len(c.cache) < int(float64(c.maxSize)*0.9) {
				break
			}
			delete(c.cache, oldestKey)
		}
	}
	c.cache[ip] = record
	c.mu.Unlock()
}
