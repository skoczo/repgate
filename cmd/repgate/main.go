package main

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/skoczo/repgate/internal/abuseipdb"
	"github.com/skoczo/repgate/internal/api"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/storage"
	"github.com/skoczo/repgate/internal/threatcheck"
)

func main() {
	setLogger()
	db := createDBAndRunDBMigrations()

	// Ensure the database connection is closed when the application exits
	defer db.Close()

	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// build threat sources based on config
	repo := storage.NewIPRepository(db, cfg)
	threatSources := buildThreadSources(cfg, repo)

	slog.Info("Configuration loaded successfully", "AbuseIPDBEnabled", cfg.AbuseIPDB.Enabled)

	slog.Info("Starting IP Auth Server")

	server := &http.Server{
		Addr:              ":8080",
		Handler:           api.NewRouter(threatSources),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	slog.Info("Server is listening on :8080")

	if err := server.ListenAndServe(); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

func buildThreadSources(cfg *config.Config, repo *storage.IPRepository) []threatcheck.ThreatSource {
	var sources []threatcheck.ThreatSource
	if cfg.AbuseIPDB.Enabled {
		sources = append(sources, &threatcheck.AbuseIPDBClient{
			APIKey: cfg.AbuseIPDB.APIKey,
			Repo:   *repo,
			Client: &abuseipdb.AbuseIPDBRestClient{
				APIKey: cfg.AbuseIPDB.APIKey,
			},
			Config: cfg,
		})
	}
	return sources
}

func setLogger() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)
}

func createDBAndRunDBMigrations() *sql.DB {
	db, err := storage.OpenSQLiteDB("data/repgate.db")
	if err != nil {
		slog.Error("Failed to open database", "error", err)
		os.Exit(1)
	}

	if err := storage.RunMigrations(db, "db/migrations/001_init.sql"); err != nil {
		slog.Error("Failed to run migrations", "error", err)
		os.Exit(1)
	}
	return db
}
