package main

import (
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/skoczo/repgate/internal/api"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/storage"
	"github.com/skoczo/repgate/internal/threatcheck"
)

// program will use -c flag to specify the config file path
// if no flag is provided, it will use the default config file path
// the default config file path is config.yaml
// the config file path is relative to the current working directory
// the config file path is a string
// the config file path is a string
func main() {
	cfgPath := flag.String("c", "config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	setLogger(cfg.LogLevel)
	db := createDBAndRunDBMigrations()

	// Ensure the database connection is closed when the application exits
	defer db.Close()

	// build threat sources based on config
	repo := storage.NewIPRepository(db, cfg)
	threatSources := buildThreadSources(cfg, repo)

	slog.Info("Configuration loaded successfully", "AbuseIPDBEnabled", cfg.AbuseIPDB.Enabled)

	slog.Info("Starting IP Auth Server")

	server := &http.Server{
		Addr:              ":8080",
		Handler:           api.NewRouter(threatSources, cfg.FailOpen),
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
		sources = append(sources, threatcheck.NewAbuseIPDBClient(cfg, repo))
	}
	return sources
}

func setLogger(logLevel string) {
	parsedLevel, err := parseLogLevel(logLevel)
	if err != nil {
		slog.Error("Failed to parse log level", "error", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parsedLevel,
	}))
	slog.SetDefault(logger)
}

func parseLogLevel(logLevel string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(logLevel))); err != nil {
		return 0, err
	}
	return level, nil
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
