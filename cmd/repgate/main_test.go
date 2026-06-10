package main

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/storage"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input       string
		expected    slog.Level
		expectError bool
	}{
		{"debug", slog.LevelDebug, false},
		{"INFO", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"ERROR", slog.LevelError, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		level, err := parseLogLevel(tt.input)
		if (err != nil) != tt.expectError {
			t.Errorf("expected error: %v, got error: %v", tt.expectError, err)
		}
		if err == nil && level != tt.expected {
			t.Errorf("expected level %v, got %v", tt.expected, level)
		}
	}
}

func TestSetLogger(t *testing.T) {
	// Should not panic or exit
	setLogger("debug")

	// Default level should be set
	if !slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		t.Error("expected debug level to be enabled")
	}
}

func TestBuildThreatSources(t *testing.T) {
	cfg := &config.Config{}
	cfg.AbuseIPDB.Enabled = true

	repo := &storage.IPRepository{}
	sources, _ := buildThreatSources(cfg, repo)

	if len(sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(sources))
	}

	cfg.AbuseIPDB.Enabled = false
	sources, _ = buildThreatSources(cfg, repo)

	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

func TestCreateDBAndRunDBMigrations(t *testing.T) {
	err := os.Chdir("../../")
	if err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir("cmd/repgate")

	db := createDBAndRunDBMigrations()
	if db == nil {
		t.Fatal("expected db to be created")
	}
	db.Close()
}
