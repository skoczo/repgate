package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/model"
)

func TestEventRepository(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	if err := RunMigrations(db, "../../db/migrations"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	repo := NewEventRepository(db)
	ctx := context.Background()

	// Test Insert and GetEvents
	e1 := &model.Event{
		IP:         "1.1.1.1",
		TargetHost: "example.com",
		TargetPath: "/admin",
		Action:     "block",
		Source:     "AbuseIPDB",
		Timestamp:  time.Now().Add(-2 * time.Hour),
	}
	e2 := &model.Event{
		IP:         "2.2.2.2",
		TargetHost: "example.com",
		TargetPath: "/home",
		Action:     "allow",
		Source:     "System",
		Timestamp:  time.Now().Add(-1 * time.Hour),
	}

	if err := repo.Insert(ctx, e1); err != nil {
		t.Fatalf("failed to insert event 1: %v", err)
	}
	if e1.ID == 0 {
		t.Fatalf("expected e1.ID to be set, got 0")
	}

	if err := repo.Insert(ctx, e2); err != nil {
		t.Fatalf("failed to insert event 2: %v", err)
	}

	events, err := repo.GetEvents(ctx, 0, 10, "")
	if err != nil {
		t.Fatalf("failed to get events: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// Because we order by ID DESC, event 2 (more recent) should be first
	if events[0].IP != "2.2.2.2" {
		t.Errorf("expected first event to be 2.2.2.2, got %s", events[0].IP)
	}
	if events[1].IP != "1.1.1.1" {
		t.Errorf("expected second event to be 1.1.1.1, got %s", events[1].IP)
	}

	// Test filtering by action
	blockedEvents, err := repo.GetEvents(ctx, 0, 10, "block")
	if err != nil {
		t.Fatalf("failed to get blocked events: %v", err)
	}
	if len(blockedEvents) != 1 {
		t.Fatalf("expected 1 blocked event, got %d", len(blockedEvents))
	}
	if blockedEvents[0].IP != "1.1.1.1" {
		t.Errorf("expected blocked event to be 1.1.1.1, got %s", blockedEvents[0].IP)
	}

	allowedEvents, err := repo.GetEvents(ctx, 0, 10, "allow")
	if err != nil {
		t.Fatalf("failed to get allowed events: %v", err)
	}
	if len(allowedEvents) != 1 {
		t.Fatalf("expected 1 allowed event, got %d", len(allowedEvents))
	}
	if allowedEvents[0].IP != "2.2.2.2" {
		t.Errorf("expected allowed event to be 2.2.2.2, got %s", allowedEvents[0].IP)
	}

	// Test pagination (beforeID)
	paginatedEvents, err := repo.GetEvents(ctx, e2.ID, 10, "")
	if err != nil {
		t.Fatalf("failed to get paginated events: %v", err)
	}
	if len(paginatedEvents) != 1 {
		t.Fatalf("expected 1 paginated event, got %d", len(paginatedEvents))
	}
	if paginatedEvents[0].IP != "1.1.1.1" {
		t.Errorf("expected paginated event to be 1.1.1.1, got %s", paginatedEvents[0].IP)
	}

	// Test DeleteOlderThan
	cutoff := time.Now().Add(-90 * time.Minute)
	deleted, err := repo.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("failed to delete older events: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted event, got %d", deleted)
	}

	eventsAfterDelete, err := repo.GetEvents(ctx, 0, 10, "")
	if err != nil {
		t.Fatalf("failed to get events: %v", err)
	}
	if len(eventsAfterDelete) != 1 {
		t.Fatalf("expected 1 event remaining, got %d", len(eventsAfterDelete))
	}
	if eventsAfterDelete[0].IP != "2.2.2.2" {
		t.Errorf("expected remaining event to be 2.2.2.2, got %s", eventsAfterDelete[0].IP)
	}
}

func TestEventRepositoryErrors(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	repo := NewEventRepository(db)
	ctx := context.Background()

	db.Close()

	e := &model.Event{
		IP: "1.1.1.1", Action: "block", Source: "System", Timestamp: time.Now(),
	}

	if err := repo.Insert(ctx, e); err == nil {
		t.Error("expected error from Insert on closed db, got nil")
	}

	if _, err := repo.GetEvents(ctx, 0, 10, ""); err == nil {
		t.Error("expected error from GetEvents on closed db, got nil")
	}

	if _, err := repo.DeleteOlderThan(ctx, time.Now()); err == nil {
		t.Error("expected error from DeleteOlderThan on closed db, got nil")
	}
}
