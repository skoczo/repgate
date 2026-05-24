package storage

import (
	"path/filepath"
	"testing"
)

func TestRunMigrations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "../../db/migrations/001_init.sql"); err != nil {
		t.Errorf("failed to run migrations: %v", err)
	}
	db.Close()
}

func TestRunMigrationsInvalidFile(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "invalid.sql"); err == nil {
		t.Errorf("expected error but got nil")
	}
	db.Close()
}

func TestRunMigrationsInvalidPath(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "invalid/path/001_init.sql"); err == nil {
		t.Errorf("expected error but got nil")
	}
	db.Close()
}

func TestRunMigrationsInvalidSQL(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "../../resources/tests/db/migrations/001_invalid.sql"); err == nil {
		t.Errorf("expected error but got nil")
	}
	db.Close()
}
