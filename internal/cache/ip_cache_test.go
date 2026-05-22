package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/model"
)

func TestIPCache(t *testing.T) {
	cache := NewIPCache(100)
	cache.Set("127.0.0.1", model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	record, ok := cache.Get("127.0.0.1")
	if !ok {
		t.Error("IP record not found")
	}
	if record.IP != "127.0.0.1" {
		t.Error("IP record not found")
	}
	if record.Status != "safe" {
		t.Error("IP record not found")
	}
}

func TestIPCacheMaxSize(t *testing.T) {
	cache := NewIPCache(100)
	for i := 0; i < 100; i++ {
		cache.Set(fmt.Sprintf("127.0.0.%d", i), model.IPRecord{IP: fmt.Sprintf("127.0.0.%d", i), Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	}
	if len(cache.cache) != 100 {
		t.Error("IP cache size is not 100")
	}
	for i := 0; i < 100; i++ {
		record, ok := cache.Get(fmt.Sprintf("127.0.0.%d", i))
		if !ok {
			t.Errorf("IP %s record not found", fmt.Sprintf("127.0.0.%d", i))
		}
		if record.IP != fmt.Sprintf("127.0.0.%d", i) {
			t.Errorf("IP %s record IP is not correct", fmt.Sprintf("127.0.0.%d", i))
		}
		if record.Status != "safe" {
			t.Errorf("IP %s record not found", fmt.Sprintf("127.0.0.%d", i))
		}
	}

	for i := 100; i < 200; i++ {
		cache.Set(fmt.Sprintf("127.0.0.%d", i), model.IPRecord{IP: fmt.Sprintf("127.0.0.%d", i), Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

		// check if record was added
		record, ok := cache.Get(fmt.Sprintf("127.0.0.%d", i))
		if !ok {
			t.Errorf("IP %s record not found", fmt.Sprintf("127.0.0.%d", i))
		}
		if record.IP != fmt.Sprintf("127.0.0.%d", i) {
			t.Errorf("IP %s record IP is not correct", fmt.Sprintf("127.0.0.%d", i))
		}
		if record.Status != "safe" {
			t.Errorf("IP %s record not found", fmt.Sprintf("127.0.0.%d", i))
		}
	}

	if len(cache.cache) > 100 {
		t.Errorf("IP cache size is not 100 but %d", len(cache.cache))
	}
}

func TestIPCacheSetExisting(t *testing.T) {
	cache := NewIPCache(100)
	cache.Set("127.0.0.1", model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

	if len(cache.cache) != 1 {
		t.Error("IP cache size is not 1")
	}

	{
		record, ok := cache.Get("127.0.0.1")
		if !ok {
			t.Error("IP record not found")
		}
		if record.Status != "safe" {
			t.Error("IP record status is not 'safe'")
		}
	}

	cache.Set("127.0.0.1", model.IPRecord{IP: "127.0.0.1", Status: "threat", Score: 100, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	record, ok := cache.Get("127.0.0.1")
	if !ok {
		t.Error("IP record not found")
	}
	if record.Status != "threat" {
		t.Error("IP record overwritten, expected status 'threat' but got 'safe'")
	}
}

func TestIPCacheRemove(t *testing.T) {
	cache := NewIPCache(100)
	cache.Set("127.0.0.1", model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

	{
		_, ok := cache.Get("127.0.0.1")
		if !ok {
			t.Error("IP record not found")
		}
	}
	{
		cache.Remove("127.0.0.1")
		_, ok := cache.Get("127.0.0.1")
		if ok {
			t.Error("IP record not removed")
		}
	}
}

func TestIPCacheSize(t *testing.T) {
	cache := NewIPCache(42)
	if cache.Size() != 42 {
		t.Errorf("expected size 42, got %d", cache.Size())
	}
}

func TestIPCacheNumOfEntries(t *testing.T) {
	cache := NewIPCache(10)
	if cache.NumOfEntries() != 0 {
		t.Errorf("expected 0 entries, got %d", cache.NumOfEntries())
	}

	cache.Set("1.1.1.1", model.IPRecord{IP: "1.1.1.1", Status: "safe"})
	cache.Set("2.2.2.2", model.IPRecord{IP: "2.2.2.2", Status: "safe"})

	if cache.NumOfEntries() != 2 {
		t.Errorf("expected 2 entries, got %d", cache.NumOfEntries())
	}

	cache.Remove("1.1.1.1")
	if cache.NumOfEntries() != 1 {
		t.Errorf("expected 1 entry, got %d", cache.NumOfEntries())
	}
}

func TestIPCacheThreatCountAndLruEviction(t *testing.T) {
	cache := NewIPCache(2)
	if cache.ThreatCount() != 0 {
		t.Errorf("expected 0 threat count, got %d", cache.ThreatCount())
	}

	// 1. Add threat IP
	cache.Set("1.1.1.1", model.IPRecord{IP: "1.1.1.1", Status: "threat"})
	if cache.ThreatCount() != 1 {
		t.Errorf("expected 1 threat count, got %d", cache.ThreatCount())
	}

	// 2. Add safe IP
	cache.Set("2.2.2.2", model.IPRecord{IP: "2.2.2.2", Status: "safe"})
	if cache.ThreatCount() != 1 {
		t.Errorf("expected 1 threat count, got %d", cache.ThreatCount())
	}

	// 3. Update threat to safe
	cache.Set("1.1.1.1", model.IPRecord{IP: "1.1.1.1", Status: "safe"})
	if cache.ThreatCount() != 0 {
		t.Errorf("expected 0 threat count, got %d", cache.ThreatCount())
	}

	// 4. Update safe to threat
	cache.Set("1.1.1.1", model.IPRecord{IP: "1.1.1.1", Status: "threat"})
	if cache.ThreatCount() != 1 {
		t.Errorf("expected 1 threat count, got %d", cache.ThreatCount())
	}

	// 5. Trigger LRU eviction of a threat (since size limit is 2, 2.2.2.2 is safe, 1.1.1.1 is threat, let's access 2.2.2.2 so 1.1.1.1 is evicted when adding 3.3.3.3)
	_, _ = cache.Get("2.2.2.2") // MRU is now 2.2.2.2, LRU is 1.1.1.1
	cache.Set("3.3.3.3", model.IPRecord{IP: "3.3.3.3", Status: "safe"}) // This evicts 1.1.1.1 (threat)
	if cache.ThreatCount() != 0 {
		t.Errorf("expected 0 threat count after threat eviction, got %d", cache.ThreatCount())
	}

	// 6. Test eviction of safe record when threat is MRU
	cache.Set("4.4.4.4", model.IPRecord{IP: "4.4.4.4", Status: "threat"}) // Cache contains 3.3.3.3 (safe) and 4.4.4.4 (threat). MRU is 4.4.4.4, LRU is 3.3.3.3
	if cache.ThreatCount() != 1 {
		t.Errorf("expected 1 threat count, got %d", cache.ThreatCount())
	}
	cache.Set("5.5.5.5", model.IPRecord{IP: "5.5.5.5", Status: "safe"}) // Evicts 3.3.3.3 (safe). Cache has 4.4.4.4 (threat) and 5.5.5.5 (safe).
	if cache.ThreatCount() != 1 {
		t.Errorf("expected 1 threat count after safe eviction, got %d", cache.ThreatCount())
	}
}

func TestIPCacheRemoveExpired(t *testing.T) {
	cache := NewIPCache(10)
	now := time.Now()

	cache.Set("1.1.1.1", model.IPRecord{IP: "1.1.1.1", Status: "threat", ExpiresAt: now.Add(-1 * time.Minute)})
	cache.Set("2.2.2.2", model.IPRecord{IP: "2.2.2.2", Status: "safe", ExpiresAt: now.Add(10 * time.Minute)})
	cache.Set("3.3.3.3", model.IPRecord{IP: "3.3.3.3", Status: "threat", ExpiresAt: now.Add(-5 * time.Minute)})

	if cache.ThreatCount() != 2 {
		t.Errorf("expected 2 threats, got %d", cache.ThreatCount())
	}
	if cache.NumOfEntries() != 3 {
		t.Errorf("expected 3 entries, got %d", cache.NumOfEntries())
	}

	cache.RemoveExpired(now)

	if cache.NumOfEntries() != 1 {
		t.Errorf("expected 1 entry left, got %d", cache.NumOfEntries())
	}
	if cache.ThreatCount() != 0 {
		t.Errorf("expected 0 threats left, got %d", cache.ThreatCount())
	}
	if _, exists := cache.Get("2.2.2.2"); !exists {
		t.Error("expected 2.2.2.2 to still exist in cache")
	}
}
