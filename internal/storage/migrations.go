package storage

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RunMigrations scans the specified directory for .sql files, sorts them
// alphabetically, and executes their contents sequentially against the db.
func RunMigrations(db *sql.DB, dirPath string) error {
	// Create schema_migrations table if not exists
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Get already applied migrations
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("failed to scan migration version: %w", err)
		}
		applied[version] = true
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			files = append(files, entry.Name())
		}
	}

	sort.Strings(files)

	for _, file := range files {
		if applied[file] {
			slog.Debug("Migration already applied, skipping: " + file)
			continue
		}

		slog.Info("Executing migration file: " + file)
		fullPath := filepath.Join(dirPath, file)
		query, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		if _, err := db.Exec(string(query)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}

		_, err = db.Exec("INSERT INTO schema_migrations (version) VALUES (?)", file)
		if err != nil {
			return fmt.Errorf("failed to record applied migration %s: %w", file, err)
		}
	}

	return nil
}
