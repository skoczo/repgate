package storage

import (
	"path/filepath"
	"testing"
)

func TestOpenSQLiteDB(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("expected ping to succeed, got %v", err)
	}

	// Open again to hit the branch where file exists
	db2, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("expected no error on existing db, got %v", err)
	}
	defer db2.Close()
	
	// Test error case with invalid path
	_, err = OpenSQLiteDB("/invalid/path/that/cannot/be/created/test.db")
	if err == nil {
		t.Fatal("expected error with invalid path")
	}
}
