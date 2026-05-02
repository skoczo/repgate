package cache

import (
	"sync"

	"github.com/skoczo/repgate/internal/model"
)

type IPCache struct {
	mu      sync.RWMutex
	cache   map[string]model.IPRecord
	maxSize int
}

func NewIPCache(maxSize int) *IPCache {
	return &IPCache{cache: make(map[string]model.IPRecord), maxSize: maxSize, mu: sync.RWMutex{}}
}

func (c *IPCache) Get(ip string) (model.IPRecord, bool) {
	c.mu.RLock()
	record, ok := c.cache[ip]
	c.mu.RUnlock()
	return record, ok
}

func (c *IPCache) Remove(ip string) {
	c.mu.Lock()
	delete(c.cache, ip)
	c.mu.Unlock()
}

func (c *IPCache) Set(ip string, record model.IPRecord) {
	// if exist in map skip record
	if _, exists := c.cache[ip]; exists {
		return
	}
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
