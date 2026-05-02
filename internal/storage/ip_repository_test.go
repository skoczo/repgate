package storage

import (
	"database/sql"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
)

func TestIPRepository(t *testing.T) {
	err, repo, _ := initialize(t)

	repo.Update(&model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	record, err := repo.GetByIp("127.0.0.1")
	if err != nil {
		t.Errorf("failed to get IP record: %v", err)
	}
	if record.IP != "127.0.0.1" {
		t.Errorf("IP record IP is not correct: %s", record.IP)
	}

	removeDatabaseFile(t)
}

// failed to save IP record
func TestIPRepositorySaveFailed(t *testing.T) {
	err, repo, db := initialize(t)

	db.Close()
	record := &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)}
	err = repo.Update(record)
	if err == nil {
		t.Errorf("expected error but got nil")
	}

	removeDatabaseFile(t)
}

func TestIPRepositoryDelete(t *testing.T) {
	err, repo, _ := initialize(t)

	repo.Update(&model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})

	record, err := repo.GetByIp("127.0.0.1")
	if err != nil {
		t.Errorf("failed to get IP record: %v", err)
	}
	if record.IP != "127.0.0.1" {
		t.Errorf("IP record IP is not correct: %s", record.IP)
	}

	err = repo.Delete("127.0.0.1")
	if err != nil {
		t.Errorf("failed to delete IP record: %v", err)
	}
	record, err = repo.GetByIp("127.0.0.1")

	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}

	if err == nil {
		t.Errorf("expected error but got nil")
	}
	removeDatabaseFile(t)
}

func TestIPRepositoryDeleteExpired(t *testing.T) {
	err, repo, _ := initialize(t)

	repo.Update(&model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	repo.Update(&model.IPRecord{IP: "127.0.0.2", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})

	err = repo.DeleteExpired(time.Now().Add(12 * time.Hour))
	if err != nil {
		t.Errorf("failed to delete expired IP records: %v", err)
	}

	record, err := repo.GetByIp("127.0.0.1")
	if err == nil {
		t.Errorf("there should be an error but got nil")
	}
	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}
	record, err = repo.GetByIp("127.0.0.2")
	if err == nil {
		t.Errorf("there should be an error but got nil")
	}
	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}
	removeDatabaseFile(t)
}

func TestIPRepositoryFailToDelete(t *testing.T) {
	err, repo, db := initialize(t)

	db.Close()
	err = repo.Delete("127.0.0.1")
	if err == nil {
		t.Errorf("expected error but got nil")
	}
	removeDatabaseFile(t)
}

func TestIPRepositoryDeleteExpiredWithNoRecords(t *testing.T) {
	err, repo, _ := initialize(t)

	err = repo.DeleteExpired(time.Now())
	if err != nil {
		t.Errorf("failed to delete expired IP records: %v", err)
	}
	removeDatabaseFile(t)
}

func TestIPRepositoryDeleteExpiredFailed(t *testing.T) {
	err, repo, db := initialize(t)

	db.Close()
	err = repo.DeleteExpired(time.Now())
	if err == nil {
		t.Errorf("expected error but got nil")
	}
	removeDatabaseFile(t)
}

func initialize(t *testing.T) (error, *IPRepository, *sql.DB) {
	db, err := OpenSQLiteDB("repgate.db")
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}

	// run migrations
	if err := RunMigrations(db, "../../db/migrations/001_init.sql"); err != nil {
		t.Errorf("failed to run migrations: %v", err)
	}
	repo := NewIPRepository(db, &config.Config{AbuseIPDB: struct {
		Enabled                  bool          `yaml:"enabled"`
		APIKey                   string        `yaml:"api_key"`
		ExpirationTime           time.Duration `yaml:"expiration_time"`
		ConfidenceScoreThreshold int           `yaml:"confidence_score_threshold"`
		CacheMaxSize             int           `yaml:"cache_max_size"`
	}{Enabled: true, APIKey: "test", ExpirationTime: 24 * time.Hour, ConfidenceScoreThreshold: 50}})
	return err, repo, db
}
