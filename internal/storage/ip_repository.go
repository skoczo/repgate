package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
)

type IPRepository struct {
	db             *sql.DB
	expirationTime time.Duration
}

func NewIPRepository(db *sql.DB, cfg *config.Config) *IPRepository {
	return &IPRepository{db: db, expirationTime: cfg.AbuseIPDB.ExpirationTime}
}

func (r *IPRepository) GetByIp(ctx context.Context, ip string) (*model.IPRecord, error) {
	query := `SELECT ip, status, score, source, checked_at, expires_at FROM ip_records WHERE ip = ? and expires_at > ?`
	row := r.db.QueryRowContext(ctx, query, ip, time.Now())

	var record model.IPRecord
	if err := row.Scan(&record.IP, &record.Status, &record.Score, &record.Source, &record.CheckedAt, &record.ExpiresAt); err != nil {
		// if error is no rows, return nil without error
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get IP record: %w", err)
	}
	return &record, nil
}

// update method should be used for saving new records and updating existing records
func (r *IPRepository) Update(ctx context.Context, record *model.IPRecord) (*model.IPRecord, error) {
	query := `
	INSERT INTO ip_records
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip) DO UPDATE SET
		status=excluded.status,
		score=excluded.score,
		source=excluded.source,
		checked_at=excluded.checked_at,
		expires_at=excluded.expires_at
	`
	_, err := r.db.ExecContext(ctx, query, record.IP, record.Status, record.Score, record.Source, time.Now(), time.Now().Add(r.expirationTime))
	if err != nil {
		return nil, fmt.Errorf("failed to save IP record: %w", err)
	}

	dbRecord, err := r.GetByIp(ctx, record.IP)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP record after saving: %w", err)
	}
	return dbRecord, nil
}

func (r *IPRepository) Delete(ctx context.Context, ip string) error {
	query := `DELETE FROM ip_records WHERE ip = ?`
	_, err := r.db.ExecContext(ctx, query, ip)
	if err != nil {
		return fmt.Errorf("failed to delete IP record: %w", err)
	}
	return nil
}

func (r *IPRepository) DeleteExpired(ctx context.Context, expiration time.Time) error {
	query := `DELETE FROM ip_records WHERE expires_at <= ?`
	result, err := r.db.ExecContext(ctx, query, expiration)
	if err != nil {
		return fmt.Errorf("failed to delete expired IP records: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}
	slog.Debug("expired IP records deleted", "count", count)
	return nil
}

func (r *IPRepository) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ip_records").Scan(&count)
	return count, err
}

func (r *IPRepository) ThreatCount(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ip_records WHERE status = 'threat'").Scan(&count)
	return count, err
}
