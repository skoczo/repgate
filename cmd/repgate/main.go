package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/skoczo/repgate/internal/api"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/storage"
	"github.com/skoczo/repgate/internal/threatcheck"
)

// program will use -c flag to specify the config file path
// if no flag is provided, it will use the default config file path
// the default config file path is config.yaml
// the config file path is relative to the current working directory
// the config file path is a string
// program will handle SIGINT and SIGTERM signals to gracefully shut down
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

	if count, err := repo.Count(context.Background()); err == nil {
		metrics.GetMetrics().AbuseIpDbDatabaseEntitiesCount.Set(float64(count))
	} else {
		slog.Error("Failed to get initial database record count", "error", err)
	}

	if threatCount, err := repo.ThreatCount(context.Background()); err == nil {
		metrics.GetMetrics().AbuseIpDbDatabaseThreatsCount.Set(float64(threatCount))
	} else {
		slog.Error("Failed to get initial database threat count", "error", err)
	}

	// start background worker to periodically clean expired records from db and caches
	go startCleanupWorker(repo, threatSources)

	slog.Info("Configuration loaded successfully", "AbuseIPDBEnabled", cfg.AbuseIPDB.Enabled)

	slog.Info("Starting IP Auth Server")

	server := &http.Server{
		Addr:              cfg.Server.Port,
		Handler:           api.NewRouter(threatSources, cfg.FailOpen, cfg.LogSafeIPs, cfg.Server.ReadTimeout),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Server is listening on " + cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	<-sigChan
	slog.Info("Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}
	slog.Info("Server exited")
}

func buildThreadSources(cfg *config.Config, repo *storage.IPRepository) []threatcheck.ThreatSource {
	var sources []threatcheck.ThreatSource
	if cfg.AbuseIPDB.Enabled {
		sources = append(sources, threatcheck.NewAbuseIPDBClient(cfg, repo))
	}
	return sources
}

func startCleanupWorker(repo *storage.IPRepository, sources []threatcheck.ThreatSource) {
	ticker := time.NewTicker(60 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		now := time.Now()
		if err := repo.DeleteExpired(context.Background(), now); err != nil {
			slog.Error("Failed to delete expired IP records from repository", "error", err)
		} else {
			if count, err := repo.Count(context.Background()); err == nil {
				metrics.GetMetrics().AbuseIpDbDatabaseEntitiesCount.Set(float64(count))
			}
			if threatCount, err := repo.ThreatCount(context.Background()); err == nil {
				metrics.GetMetrics().AbuseIpDbDatabaseThreatsCount.Set(float64(threatCount))
			}
		}

		for _, source := range sources {
			source.CleanExpired(now)
		}
	}
}

func setLogger(logLevel string) {
	parsedLevel, err := parseLogLevel(logLevel)
	if err != nil {
		slog.Error("Failed to parse log level", "error", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
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


