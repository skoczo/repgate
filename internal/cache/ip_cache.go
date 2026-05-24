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
	mu          sync.RWMutex
	cache       map[string]*CacheEntry
	lru         *list.List
	maxSize     int
	threatCount int
	Now         func() time.Time
}

func NewIPCache(maxSize int) *IPCache {
	return &IPCache{
		cache:       make(map[string]*CacheEntry),
		lru:         list.New(),
		maxSize:     maxSize,
		threatCount: 0,
		Now:         time.Now,
	}
}

func (c *IPCache) Get(ip string) (model.IPRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.cache[ip]; exists {
		// Move to front (most recently used)
		c.lru.MoveToFront(entry.element)
		entry.timestamp = c.Now()
		return entry.record, true
	}
	return model.IPRecord{}, false
}

func (c *IPCache) Set(ip string, record model.IPRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.cache[ip]; exists {
		// Update existing entry
		if entry.record.Status == "threat" && record.Status != "threat" {
			c.threatCount--
		} else if entry.record.Status != "threat" && record.Status == "threat" {
			c.threatCount++
		}
		
		entry.record = record
		entry.timestamp = c.Now()
		c.lru.MoveToFront(entry.element)
		return
	}

	// Evict if at capacity (O(1) with LRU)
	if len(c.cache) >= c.maxSize {
		c.evictLRU()
	}

	// Add new entry
	if record.Status == "threat" {
		c.threatCount++
	}
	element := c.lru.PushFront(ip)
	c.cache[ip] = &CacheEntry{
		record:    record,
		element:   element,
		timestamp: c.Now(),
	}
}

func (c *IPCache) Remove(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.cache[ip]; exists {
		if entry.record.Status == "threat" {
			c.threatCount--
		}
		c.lru.Remove(entry.element)
		delete(c.cache, ip)
	}
}

func (c *IPCache) evictLRU() {
	// Remove least recently used entry
	element := c.lru.Back()
	if element != nil {
		ip := element.Value.(string)
		if entry, exists := c.cache[ip]; exists {
			if entry.record.Status == "threat" {
				c.threatCount--
			}
			delete(c.cache, ip)
		}
		c.lru.Remove(element)
	}
}

func (c *IPCache) RemoveExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for ip, entry := range c.cache {
		if entry.record.ExpiresAt.Before(now) {
			if entry.record.Status == "threat" {
				c.threatCount--
			}
			c.lru.Remove(entry.element)
			delete(c.cache, ip)
		}
	}
}

func (c *IPCache) Size() int {
	return c.maxSize
}

func (c *IPCache) NumOfEntries() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

func (c *IPCache) ThreatCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.threatCount
}

