//go:build integration

package integration

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Create a temporary directory for the database file
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	
	db, err := storage.OpenSQLiteDB(dbPath)
	require.NoError(t, err, "Should open SQLite DB")

	// Adjust the path to the migration file based on the test execution location
	err = storage.RunMigrations(db, "../../db/migrations/001_init.sql")
	require.NoError(t, err, "Should run migrations successfully")

	return db
}

func TestIntegration_IPRepository(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	cfg := &config.Config{}
	cfg.AbuseIPDB.ExpirationTime = 24 * time.Hour
	repo := storage.NewIPRepository(db, cfg)

	// 1. Test Insert (Update)
	record := &model.IPRecord{
		IP:        "192.168.100.1",
		Status:    "threat",
		Score:     99,
		Source:    "IntegrationTest",
	}

	saved, err := repo.Update(record)
	require.NoError(t, err)
	require.NotNil(t, saved)
	assert.Equal(t, "192.168.100.1", saved.IP)
	assert.Equal(t, "threat", saved.Status)

	// 2. Test Get
	found, err := repo.GetByIp("192.168.100.1")
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, 99, found.Score)

	// 3. Test Update (Overwrite existing)
	found.Score = 50
	found.Status = "safe"
	updated, err := repo.Update(found)
	require.NoError(t, err)
	assert.Equal(t, 50, updated.Score)
	assert.Equal(t, "safe", updated.Status)

	// 4. Test Delete
	err = repo.Delete("192.168.100.1")
	require.NoError(t, err)

	// Ensure deleted
	missing, err := repo.GetByIp("192.168.100.1")
	assert.ErrorIs(t, err, sql.ErrNoRows, "Expected ErrNoRows after deletion")
	assert.Nil(t, missing)
}
