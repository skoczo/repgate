package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/skoczo/repgate/internal/model"
)

type EventRepository struct {
	db *sql.DB
}

func NewEventRepository(db *sql.DB) *EventRepository {
	return &EventRepository{db: db}
}

func (r *EventRepository) Insert(ctx context.Context, e *model.Event) error {
	query := `
	INSERT INTO events (ip, target_host, target_path, action, source, timestamp)
	VALUES (?, ?, ?, ?, ?, ?)
	`
	res, err := r.db.ExecContext(ctx, query, e.IP, e.TargetHost, e.TargetPath, e.Action, e.Source, e.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}
	id, err := res.LastInsertId()
	if err == nil {
		e.ID = id
	}
	return nil
}

func (r *EventRepository) GetEvents(ctx context.Context, beforeID int64, limit int, action string) ([]model.Event, error) {
	var rows *sql.Rows
	var err error

	query := `
	SELECT id, ip, target_host, target_path, action, source, timestamp
	FROM events
	`
	var conditions []string
	var args []interface{}

	if beforeID > 0 {
		conditions = append(conditions, "id < ?")
		args = append(args, beforeID)
	}

	if action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, action)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err = r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []model.Event
	for rows.Next() {
		var e model.Event
		if err := rows.Scan(&e.ID, &e.IP, &e.TargetHost, &e.TargetPath, &e.Action, &e.Source, &e.Timestamp); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, e)
	}
	// Return empty slice instead of nil for clean JSON responses
	if events == nil {
		events = []model.Event{}
	}
	return events, nil
}

func (r *EventRepository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	query := `DELETE FROM events WHERE timestamp <= ?`
	res, err := r.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired events: %w", err)
	}
	return res.RowsAffected()
}
