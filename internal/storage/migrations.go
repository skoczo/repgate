package storage

import (
	"database/sql"
	"fmt"
	"os"
)

func RunMigrations(db *sql.DB, path string) error {
	query, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read migration file: %w", err)
	}

	if _, err := db.Exec(string(query)); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	return nil
}
