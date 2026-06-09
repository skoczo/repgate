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

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/api"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/event"
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

	// Create repositories
	ipRepo := storage.NewIPRepository(db, cfg)
	eventRepo := storage.NewEventRepository(db)

	// Create services
	eventService := event.NewService(eventRepo, cfg.LiveStreamRetentionDays)

	// Build threat sources based on config
	threatSources := buildThreadSources(cfg, ipRepo)

	// Set initial metrics
	if count, err := ipRepo.Count(context.Background()); err == nil {
		metrics.GetMetrics().AbuseIpDbDatabaseEntitiesCount.Set(float64(count))
	} else {
		slog.Error("Failed to get initial database record count", "error", err)
	}

	if threatCount, err := ipRepo.ThreatCount(context.Background()); err == nil {
		metrics.GetMetrics().AbuseIpDbDatabaseThreatsCount.Set(float64(threatCount))
	} else {
		slog.Error("Failed to get initial database threat count", "error", err)
	}

	// Perform initial cleanup of expired events at startup if retention is enabled (> 0)
	if cfg.LiveStreamRetentionDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -cfg.LiveStreamRetentionDays)
		if affected, err := eventRepo.DeleteOlderThan(context.Background(), cutoff); err != nil {
			slog.Error("Failed to delete expired events at startup", "error", err)
		} else if affected > 0 {
			slog.Info("Cleaned up expired live stream events at startup", "count", affected, "cutoff", cutoff)
		}
	}

	// start background worker to periodically clean expired records from db, events, and caches
	go startCleanupWorker(ipRepo, eventRepo, cfg.LiveStreamRetentionDays, threatSources)

	slog.Info("Configuration loaded successfully", "AbuseIPDBEnabled", cfg.AbuseIPDB.Enabled)

	var adService *activedefence.Service
	if cfg.ActiveDefence.Enabled {
		var caches []activedefence.Cache
		for _, source := range threatSources {
			if client, ok := source.(*threatcheck.AbuseIPDBThreatSource); ok {
				caches = append(caches, client.IPCache)
			}
		}
		var err error
		adService, err = activedefence.NewService(ipRepo, caches, cfg.ActiveDefence.ExpirationTime, cfg.ActiveDefence.HoneytokenPaths)
		if err != nil {
			slog.Error("Failed to initialize active defence service", "error", err)
			os.Exit(1)
		}
		slog.Info("Active defence service initialized", "honeytoken_paths_count", len(cfg.ActiveDefence.HoneytokenPaths))
	}

	slog.Info("Starting HTTP Server")

	server := &http.Server{
		Addr:              cfg.Server.Port,
		Handler:           api.NewRouter(threatSources, adService, cfg.FailOpen, cfg.LogSafeIPs, cfg.Server.ReadTimeout, eventService, ipRepo),
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

func startCleanupWorker(repo *storage.IPRepository, eventRepo *storage.EventRepository, retentionDays int, sources []threatcheck.ThreatSource) {
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

		// Clean up expired events
		if retentionDays > 0 {
			cutoff := now.AddDate(0, 0, -retentionDays)
			if affected, err := eventRepo.DeleteOlderThan(context.Background(), cutoff); err != nil {
				slog.Error("Failed to delete expired events", "error", err)
			} else if affected > 0 {
				slog.Info("Cleaned up expired live stream events", "count", affected, "cutoff", cutoff)
			}
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

	if err := storage.RunMigrations(db, "db/migrations"); err != nil {
		slog.Error("Failed to run migrations", "error", err)
		os.Exit(1)
	}
	return db
}
