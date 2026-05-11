package storage

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func OpenSQLiteDB(dbPath string) (*sql.DB, error) {
	// create empty file and all parent directories if it does not exist
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if err := os.MkdirAll("data", 0755); err != nil {
			return nil, fmt.Errorf("failed to create data directory: %w", err)
		}
		file, err := os.Create(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create database file: %w", err)
		}
		file.Close()
	}

	// Open the SQLite database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite does not support concurrent writes

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}
