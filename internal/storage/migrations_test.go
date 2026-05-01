package storage

import (
	"os"
	"testing"
)

func removeDatabaseFile(t *testing.T) {
	if err := os.Remove("repgate.db"); err != nil {
		t.Errorf("failed to remove database file: %v", err)
	}
}

func TestRunMigrations(t *testing.T) {
	db, err := OpenSQLiteDB("repgate.db")
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "../../db/migrations/001_init.sql"); err != nil {
		t.Errorf("failed to run migrations: %v", err)
	}
	db.Close()
	removeDatabaseFile(t)
}

func TestRunMigrationsInvalidFile(t *testing.T) {
	db, err := OpenSQLiteDB("repgate.db")
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "invalid.sql"); err == nil {
		t.Errorf("expected error but got nil")
	}
	db.Close()
	removeDatabaseFile(t)
}

func TestRunMigrationsInvalidPath(t *testing.T) {
	db, err := OpenSQLiteDB("repgate.db")
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "invalid/path/001_init.sql"); err == nil {
		t.Errorf("expected error but got nil")
	}
	db.Close()
	removeDatabaseFile(t)
}

func TestRunMigrationsInvalidSQL(t *testing.T) {
	db, err := OpenSQLiteDB("repgate.db")
	if err != nil {
		t.Errorf("failed to open database: %v", err)
	}
	if err := RunMigrations(db, "../../resources/tests/db/migrations/001_invalid.sql"); err == nil {
		t.Errorf("expected error but got nil")
	}
	db.Close()
	removeDatabaseFile(t)
}
