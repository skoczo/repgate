package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/skoczo/repgate/internal/api"
	"github.com/skoczo/repgate/internal/storage"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	db, err := storage.OpenSQLiteDB("data/repgate.db")
	if err != nil {
		slog.Error("Failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := storage.RunMigrations(db, "db/migrations/001_init.sql"); err != nil {
		slog.Error("Failed to run migrations", "error", err)
		os.Exit(1)
	}

	ipRepo := storage.NewIPRepository(db)
	_ = ipRepo // Placeholder to avoid unused variable error

	slog.Info("Starting IP Auth Server")

	server := &http.Server{
		Addr:              ":8080",
		Handler:           api.NewRouter(),
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
