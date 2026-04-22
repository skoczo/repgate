package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/skoczo/repgate/internal/model"
)

type IPRepository struct {
	db *sql.DB
}

func NewIPRepository(db *sql.DB) *IPRepository {
	return &IPRepository{db: db}
}

func (r *IPRepository) Save(record *model.IPRecord) error {
	query := `
	INSERT INTO ip_records (ip, status, score, source, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip) DO UPDATE SET
		status=excluded.status,
		score=excluded.score,
		source=excluded.source,
		updated_at=excluded.updated_at
	`
	_, err := r.db.Exec(query,
		record.IP,
		record.Status,
		record.Score,
		record.Source,
		time.Now(),
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to save IP record: %w", err)
	}
	return nil
}

func (r *IPRepository) GetByIp(ip string) (*model.IPRecord, error) {
	query := `SELECT ip, status, score, source, created_at, updated_at FROM ip_records WHERE ip = ?`
	row := r.db.QueryRow(query, ip)

	var record model.IPRecord
	if err := row.Scan(&record.IP, &record.Status, &record.Score, &record.Source, &record.CreatedAt, &record.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get IP record: %w", err)
	}
	return &record, nil
}

func (r *IPRepository) Update(record *model.IPRecord) error {
	query := `
	UPDATE ip_records
	SET status = ?, score = ?, source = ?, updated_at = ?
	WHERE ip = ?
	`
	_, err := r.db.Exec(query,
		record.Status,
		record.Score,
		record.Source,
		time.Now(),
		record.IP,
	)
	if err != nil {
		return fmt.Errorf("failed to update IP record: %w", err)
	}
	return nil
}

func (r *IPRepository) Delete(ip string) error {
	query := `DELETE FROM ip_records WHERE ip = ?`
	_, err := r.db.Exec(query, ip)
	if err != nil {
		return fmt.Errorf("failed to delete IP record: %w", err)
	}
	return nil
}

func (r *IPRepository) DeleteExpired(expiration time.Duration) error {
	query := `DELETE FROM ip_records WHERE updated_at < ?`
	expirationTime := time.Now().Add(-expiration)
	_, err := r.db.Exec(query, expirationTime)
	if err != nil {
		return fmt.Errorf("failed to delete expired IP records: %w", err)
	}
	return nil
}
