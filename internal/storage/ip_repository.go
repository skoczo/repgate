package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
)

type IPRepository struct {
	db             *sql.DB
	expirationTime time.Duration
	Now            func() time.Time
}

func NewIPRepository(db *sql.DB, cfg *config.Config) *IPRepository {
	return &IPRepository{db: db, expirationTime: cfg.AbuseIPDB.ExpirationTime, Now: time.Now}
}

func (r *IPRepository) GetByIp(ctx context.Context, ip string) (*model.IPRecord, error) {
	query := `SELECT ip, status, score, source, checked_at, expires_at, reported FROM ip_records WHERE ip = ? and expires_at > ?`
	row := r.db.QueryRowContext(ctx, query, ip, r.Now())

	var record model.IPRecord
	if err := row.Scan(&record.IP, &record.Status, &record.Score, &record.Source, &record.CheckedAt, &record.ExpiresAt, &record.Reported); err != nil {
		// if error is no rows, return nil without error
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get IP record: %w", err)
	}
	return &record, nil
}

func (r *IPRepository) GetRecord(ctx context.Context, ip string) (*model.IPRecord, error) {
	query := `SELECT ip, status, score, source, checked_at, expires_at, reported FROM ip_records WHERE ip = ?`
	row := r.db.QueryRowContext(ctx, query, ip)

	var record model.IPRecord
	if err := row.Scan(&record.IP, &record.Status, &record.Score, &record.Source, &record.CheckedAt, &record.ExpiresAt, &record.Reported); err != nil {
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
	INSERT INTO ip_records (ip, status, score, source, checked_at, expires_at, reported)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip) DO UPDATE SET
		status=excluded.status,
		score=excluded.score,
		source=excluded.source,
		checked_at=excluded.checked_at,
		expires_at=excluded.expires_at,
		reported=excluded.reported
	`
	checkedAt := record.CheckedAt
	if checkedAt.IsZero() {
		checkedAt = r.Now()
	}
	expiresAt := record.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = r.Now().Add(r.expirationTime)
	}

	_, err := r.db.ExecContext(ctx, query, record.IP, record.Status, record.Score, record.Source, checkedAt, expiresAt, record.Reported)
	if err != nil {
		return nil, fmt.Errorf("failed to save IP record: %w", err)
	}

	dbRecord, err := r.GetRecord(ctx, record.IP)
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

func (r *IPRepository) ListRecords(ctx context.Context, limit, offset int, search string, status string, sortBy string, sortOrder string) ([]model.IPRecord, int, error) {
	allowedSortFields := map[string]string{
		"ip":         "ip",
		"status":     "status",
		"score":      "score",
		"source":     "source",
		"checked_at": "checked_at",
		"expires_at": "expires_at",
	}
	sortCol, ok := allowedSortFields[strings.ToLower(sortBy)]
	if !ok {
		sortCol = "expires_at"
	}

	orderDir := "DESC"
	if strings.ToUpper(sortOrder) == "ASC" {
		orderDir = "ASC"
	}

	whereClause := ""
	var args []any
	var conditions []string

	if search != "" {
		conditions = append(conditions, "ip LIKE ?")
		args = append(args, "%"+search+"%")
	}
	if status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}

	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM ip_records %s", whereClause)
	var totalCount int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count IP records: %w", err)
	}

	query := fmt.Sprintf("SELECT ip, status, score, source, checked_at, expires_at, reported FROM ip_records %s ORDER BY %s %s LIMIT ? OFFSET ?", whereClause, sortCol, orderDir)
	queryArgs := append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query IP records: %w", err)
	}
	defer rows.Close()

	var records []model.IPRecord
	for rows.Next() {
		var record model.IPRecord
		if err := rows.Scan(&record.IP, &record.Status, &record.Score, &record.Source, &record.CheckedAt, &record.ExpiresAt, &record.Reported); err != nil {
			return nil, 0, fmt.Errorf("failed to scan IP record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error reading rows: %w", err)
	}
	return records, totalCount, nil
}
