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
	if record.Status != "safe" {
		t.Error("IP record overwritten, expected status 'safe' but got 'threat'")
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
