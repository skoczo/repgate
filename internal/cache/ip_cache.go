package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/skoczo/repgate/internal/model"
)

type CacheEntry struct {
	record    model.IPRecord
	element   *list.Element
	timestamp time.Time
}

type IPCache struct {
	mu      sync.RWMutex
	cache   map[string]*CacheEntry
	lru     *list.List
	maxSize int
}

func NewIPCache(maxSize int) *IPCache {
	return &IPCache{
		cache:   make(map[string]*CacheEntry),
		lru:     list.New(),
		maxSize: maxSize,
	}
}

func (c *IPCache) Get(ip string) (model.IPRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.cache[ip]; exists {
		// Move to front (most recently used)
		c.lru.MoveToFront(entry.element)
		entry.timestamp = time.Now()
		return entry.record, true
	}
	return model.IPRecord{}, false
}

func (c *IPCache) Set(ip string, record model.IPRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.cache[ip]; exists {
		// Update existing entry
		entry.record = record
		entry.timestamp = time.Now()
		c.lru.MoveToFront(entry.element)
		return
	}

	// Evict if at capacity (O(1) with LRU)
	if len(c.cache) >= c.maxSize {
		c.evictLRU()
	}

	// Add new entry
	element := c.lru.PushFront(ip)
	c.cache[ip] = &CacheEntry{
		record:    record,
		element:   element,
		timestamp: time.Now(),
	}
}

func (c *IPCache) Remove(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.cache[ip]; exists {
		c.lru.Remove(entry.element)
		delete(c.cache, ip)
	}
}

func (c *IPCache) evictLRU() {
	// Remove least recently used entry
	element := c.lru.Back()
	if element != nil {
		ip := element.Value.(string)
		delete(c.cache, ip)
		c.lru.Remove(element)
	}
}
