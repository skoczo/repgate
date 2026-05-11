package threatcheck

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/storage"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) (*sql.DB, string) {
	f, err := os.CreateTemp("", "testdb-*.sqlite")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	f.Close()

	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	err = storage.RunMigrations(db, "../../db/migrations/001_init.sql")
	if err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return db, f.Name()
}

func TestAbuseIPDBClient(t *testing.T) {
	db, dbPath := setupTestDB(t)
	defer db.Close()
	defer os.Remove(dbPath)

	cfg := &config.Config{
		LogLevel: "debug",
		FailOpen: false,
	}
	cfg.AbuseIPDB.Enabled = true
	cfg.AbuseIPDB.APIKey = "test-key"
	cfg.AbuseIPDB.ConfidenceScoreThreshold = 90
	cfg.AbuseIPDB.CacheMaxSize = 10
	cfg.AbuseIPDB.ExpirationTime = 1 * time.Hour

	repo := storage.NewIPRepository(db, cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"abuseConfidenceScore": 95}}`)
	}))
	defer server.Close()

	client := NewAbuseIPDBClient(cfg, repo)
	client.Client.AbustIPRestUrl = server.URL + "?ipAddress=%s"

	if client.Name() != "AbuseIPDB" {
		t.Errorf("expected name AbuseIPDB, got %s", client.Name())
	}

	if !client.Enabled() {
		t.Error("expected enabled to be true")
	}

	// Test 1: IP not in cache or DB
	res, err := client.CheckIP("1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsThreat {
		t.Error("expected IP to be a threat due to score 95")
	}
	if res.IP != "1.1.1.1" {
		t.Errorf("expected IP 1.1.1.1, got %s", res.IP)
	}

	// Test 2: IP is now in Cache
	res, err = client.CheckIP("1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsThreat {
		t.Error("expected IP to be a threat from cache")
	}

	// Modify server to return lower score for another IP
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"abuseConfidenceScore": 50}}`)
	}))
	defer server2.Close()
	client.Client.AbustIPRestUrl = server2.URL + "?ipAddress=%s"

	res, err = client.CheckIP("2.2.2.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsThreat {
		t.Error("expected IP not to be a threat due to score 50")
	}

	// Test 3: clear cache, should be found in DB
	client.IPCache.Remove("1.1.1.1")
	res, err = client.CheckIP("1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsThreat {
		t.Error("expected IP to be a threat from DB")
	}

	// Test 4: cache expiration (manual injection)
	// We inject an expired record into the cache directly to trigger cleanExpiredIP
	client.IPCache.Set("3.3.3.3", model.IPRecord{
		IP:        "3.3.3.3",
		Status:    "threat",
		Score:     100,
		Source:    "AbuseIPDB",
		CheckedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	})
	
	// mock server returns 50 for this IP
	res, err = client.CheckIP("3.3.3.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsThreat {
		t.Error("expected IP to be re-fetched and not be a threat")
	}

	// Verify it's no longer expired in cache
	cached_result, exists := client.IPCache.Get("3.3.3.3")
	if !exists {
		t.Error("expected IP to be re-cached")
	}
	if cached_result.ExpiresAt.Before(time.Now()) {
		t.Error("expected new cache entry to not be expired")
	}

	// Test 5: API error
	serverErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer serverErr.Close()
	client.Client.AbustIPRestUrl = serverErr.URL + "?ipAddress=%s"

	_, err = client.CheckIP("4.4.4.4")
	if err == nil {
		t.Fatal("expected error on API failure")
	}
}
