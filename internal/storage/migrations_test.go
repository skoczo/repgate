package storage

import (
	"os"
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
	if err := RunMigrations(db, "../../db/migrations"); err != nil {
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
	if err := RunMigrations(db, "invalid_dir"); err == nil {
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
	if err := RunMigrations(db, "invalid/path"); err == nil {
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
	if err := RunMigrations(db, "../../resources/tests/db/migrations"); err == nil {
		t.Errorf("expected error but got nil")
	}
	db.Close()
}

func TestRunMigrationsOrder(t *testing.T) {
	tempDir := t.TempDir()

	// Create test migrations directory
	migrationsDir := filepath.Join(tempDir, "migrations")
	if err := os.Mkdir(migrationsDir, 0755); err != nil {
		t.Fatalf("failed to create migrations dir: %v", err)
	}

	// 001_create.sql: Creates table
	err := os.WriteFile(filepath.Join(migrationsDir, "001_create.sql"), []byte(`
		CREATE TABLE order_check (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			step TEXT
		);
	`), 0644)
	if err != nil {
		t.Fatalf("failed to write migration 1: %v", err)
	}

	// 002_first.sql: Inserts 'first'
	err = os.WriteFile(filepath.Join(migrationsDir, "002_first.sql"), []byte(`
		INSERT INTO order_check (step) VALUES ('first');
	`), 0644)
	if err != nil {
		t.Fatalf("failed to write migration 2: %v", err)
	}

	// 003_second.sql: Inserts 'second'
	err = os.WriteFile(filepath.Join(migrationsDir, "003_second.sql"), []byte(`
		INSERT INTO order_check (step) VALUES ('second');
	`), 0644)
	if err != nil {
		t.Fatalf("failed to write migration 3: %v", err)
	}

	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	if err := RunMigrations(db, migrationsDir); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Verify that table exists and rows were inserted in the correct alphabetical order
	rows, err := db.Query("SELECT step FROM order_check ORDER BY id ASC")
	if err != nil {
		t.Fatalf("failed to query order_check: %v", err)
	}
	defer rows.Close()

	var steps []string
	for rows.Next() {
		var step string
		if err := rows.Scan(&step); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		steps = append(steps, step)
	}

	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}

	if steps[0] != "first" || steps[1] != "second" {
		t.Errorf("expected ['first', 'second'], got %v", steps)
	}
}
