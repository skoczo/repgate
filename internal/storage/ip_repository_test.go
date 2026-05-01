package storage

import (
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
)

func TestIPRepository(t *testing.T) {
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
	}{Enabled: true, APIKey: "test", ExpirationTime: 24 * time.Hour, ConfidenceScoreThreshold: 50}})

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
	db, err := OpenSQLiteDB("repgate.db")
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}

	repo := NewIPRepository(db, &config.Config{AbuseIPDB: struct {
		Enabled                  bool          `yaml:"enabled"`
		APIKey                   string        `yaml:"api_key"`
		ExpirationTime           time.Duration `yaml:"expiration_time"`
		ConfidenceScoreThreshold int           `yaml:"confidence_score_threshold"`
	}{Enabled: true, APIKey: "test", ExpirationTime: 24 * time.Hour, ConfidenceScoreThreshold: 50}})
	record := &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)}
	err = repo.Update(record)
	if err == nil {
		t.Errorf("expected error but got nil")
	}

	removeDatabaseFile(t)
}
