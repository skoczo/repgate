package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
)

func (r *IPRepository) testCtx() context.Context {
	return context.Background()
}

func TestIPRepository(t *testing.T) {
	err, repo, _ := initialize(t)

	repo.Update(context.Background(), &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	record, err := repo.GetByIp(context.Background(), "127.0.0.1")
	if err != nil {
		t.Errorf("failed to get IP record: %v", err)
	}
	if record.IP != "127.0.0.1" {
		t.Errorf("IP record IP is not correct: %s", record.IP)
	}
}

// failed to save IP record
func TestIPRepositorySaveFailed(t *testing.T) {
	err, repo, db := initialize(t)

	db.Close()
	record := &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)}
	record, err = repo.Update(context.Background(), record)
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryDelete(t *testing.T) {
	err, repo, _ := initialize(t)

	repo.Update(context.Background(), &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})

	record, err := repo.GetByIp(context.Background(), "127.0.0.1")
	if err != nil {
		t.Errorf("failed to get IP record: %v", err)
	}
	if record.IP != "127.0.0.1" {
		t.Errorf("IP record IP is not correct: %s", record.IP)
	}

	err = repo.Delete(context.Background(), "127.0.0.1")
	if err != nil {
		t.Errorf("failed to delete IP record: %v", err)
	}
	record, err = repo.GetByIp(context.Background(), "127.0.0.1")

	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}

	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryDeleteExpired(t *testing.T) {
	err, repo, _ := initialize(t)

	// Insert expired records directly
	_, err = repo.db.Exec(`INSERT INTO ip_records VALUES (?, ?, ?, ?, ?, ?)`, "127.0.0.1", "safe", 0, "test", time.Now(), time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("failed to insert test record: %v", err)
	}
	_, err = repo.db.Exec(`INSERT INTO ip_records VALUES (?, ?, ?, ?, ?, ?)`, "127.0.0.2", "safe", 0, "test", time.Now(), time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("failed to insert test record: %v", err)
	}

	err = repo.DeleteExpired(context.Background(), time.Now())
	if err != nil {
		t.Errorf("failed to delete expired IP records: %v", err)
	}

	record, err := repo.GetByIp(context.Background(), "127.0.0.1")
	if err == nil {
		t.Errorf("there should be an error but got nil")
	}
	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}
	record, err = repo.GetByIp(context.Background(), "127.0.0.2")
	if err == nil {
		t.Errorf("there should be an error but got nil")
	}
	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}
}

func TestIPRepositoryFailToDelete(t *testing.T) {
	err, repo, db := initialize(t)

	db.Close()
	err = repo.Delete(context.Background(), "127.0.0.1")
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryDeleteExpiredWithNoRecords(t *testing.T) {
	err, repo, _ := initialize(t)

	err = repo.DeleteExpired(context.Background(), time.Now())
	if err != nil {
		t.Errorf("failed to delete expired IP records: %v", err)
	}
}

func TestIPRepositoryDeleteExpiredFailed(t *testing.T) {
	err, repo, db := initialize(t)

	db.Close()
	err = repo.DeleteExpired(context.Background(), time.Now())
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryCount(t *testing.T) {
	_, repo, db := initialize(t)
	defer db.Close()

	// Initial count should be 0
	count, err := repo.Count(context.Background())
	if err != nil {
		t.Fatalf("expected no error from Count(), got %v", err)
	}
	if count != 0 {
		t.Errorf("expected count to be 0, got %d", count)
	}

	threatCount, err := repo.ThreatCount(context.Background())
	if err != nil {
		t.Fatalf("expected no error from ThreatCount(), got %v", err)
	}
	if threatCount != 0 {
		t.Errorf("expected threatCount to be 0, got %d", threatCount)
	}

	// Insert a threat record
	_, err = repo.Update(context.Background(), &model.IPRecord{IP: "1.2.3.4", Status: "threat", Score: 95, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	// Insert a safe record
	_, err = repo.Update(context.Background(), &model.IPRecord{IP: "1.2.3.5", Status: "safe", Score: 10, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	count, err = repo.Count(context.Background())
	if err != nil {
		t.Fatalf("expected no error from Count(), got %v", err)
	}
	if count != 2 {
		t.Errorf("expected count to be 2, got %d", count)
	}

	threatCount, err = repo.ThreatCount(context.Background())
	if err != nil {
		t.Fatalf("expected no error from ThreatCount(), got %v", err)
	}
	if threatCount != 1 {
		t.Errorf("expected threatCount to be 1, got %d", threatCount)
	}
}

func TestIPRepositoryCountFailed(t *testing.T) {
	_, repo, db := initialize(t)
	db.Close()
	_, err := repo.Count(context.Background())
	if err == nil {
		t.Error("expected error from Count() when database is closed, got nil")
	}
}

func initialize(t *testing.T) (error, *IPRepository, *sql.DB) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}

	// run migrations
	if err := RunMigrations(db, "../../db/migrations"); err != nil {
		t.Errorf("failed to run migrations: %v", err)
	}
	repo := NewIPRepository(db, &config.Config{AbuseIPDB: struct {
		Enabled                  bool          `yaml:"enabled"`
		APIKey                   string        `yaml:"api_key"`
		ExpirationTime           time.Duration `yaml:"expiration_time"`
		ConfidenceScoreThreshold int           `yaml:"confidence_score_threshold"`
		CacheMaxSize             int           `yaml:"cache_max_size"`
		CircuitBreaker           struct {
			MaxRetries     int           `yaml:"max_retries"`
			CoolDownPeriod time.Duration `yaml:"cool_down_period"`
			OpenOnError    bool          `yaml:"open_on_error"`
		} `yaml:"circuit_breaker"`
	}{Enabled: true, APIKey: "test", ExpirationTime: 24 * time.Hour, ConfidenceScoreThreshold: 50}})
	return err, repo, db
}

func TestIPRepositoryGetRecord(t *testing.T) {
	_, repo, db := initialize(t)
	defer db.Close()

	// Insert an expired record
	expiredAt := time.Now().Add(-1 * time.Hour)
	_, err := repo.db.Exec(`INSERT INTO ip_records VALUES (?, ?, ?, ?, ?, ?)`, "10.0.0.1", "threat", 95, "test", time.Now(), expiredAt)
	if err != nil {
		t.Fatalf("failed to insert test record: %v", err)
	}

	// GetByIp should return sql.ErrNoRows because it is expired
	_, err = repo.GetByIp(context.Background(), "10.0.0.1")
	if err != sql.ErrNoRows {
		t.Errorf("expected ErrNoRows, got: %v", err)
	}

	// GetRecord should return the record even though it is expired
	record, err := repo.GetRecord(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("expected no error from GetRecord, got: %v", err)
	}
	if record.IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got: %s", record.IP)
	}
	if record.Status != "threat" {
		t.Errorf("expected status 'threat', got: %s", record.Status)
	}
}
