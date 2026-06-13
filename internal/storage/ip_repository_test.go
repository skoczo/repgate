package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
)

func (r *IPRepository) testCtx() context.Context {
	return context.Background()
}

func TestIPRepository(t *testing.T) {
	repo, db := initialize(t)
	defer db.Close()

	_, err := repo.Update(context.Background(), &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("failed to update record: %v", err)
	}

	record, err := repo.GetByIp(context.Background(), "127.0.0.1")
	if err != nil {
		t.Errorf("failed to get IP record: %v", err)
	}
	if record.IP != "127.0.0.1" {
		t.Errorf("IP record IP is not correct: %s", record.IP)
	}
}

// failed to save IP record
func TestIPRepositorySaveFailed(t *testing.T) {
	repo, db := initialize(t)
	db.Close()

	record := &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)}
	_, err := repo.Update(context.Background(), record)
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryDelete(t *testing.T) {
	repo, db := initialize(t)
	defer db.Close()

	_, err := repo.Update(context.Background(), &model.IPRecord{IP: "127.0.0.1", Status: "safe", Score: 0, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	record, err := repo.GetByIp(context.Background(), "127.0.0.1")
	if err != nil {
		t.Errorf("failed to get IP record: %v", err)
	}
	if record.IP != "127.0.0.1" {
		t.Errorf("IP record IP is not correct: %s", record.IP)
	}

	err = repo.Delete(context.Background(), "127.0.0.1")
	if err != nil {
		t.Errorf("failed to delete IP record: %v", err)
	}
	record, err = repo.GetByIp(context.Background(), "127.0.0.1")

	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}

	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryDeleteExpired(t *testing.T) {
	repo, db := initialize(t)
	defer db.Close()

	// Insert expired records directly
	_, err := repo.db.Exec(`INSERT INTO ip_records VALUES (?, ?, ?, ?, ?, ?, ?)`, "127.0.0.1", "safe", 0, "test", time.Now(), time.Now().Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("failed to insert test record: %v", err)
	}
	_, err = repo.db.Exec(`INSERT INTO ip_records VALUES (?, ?, ?, ?, ?, ?, ?)`, "127.0.0.2", "safe", 0, "test", time.Now(), time.Now().Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("failed to insert test record: %v", err)
	}

	err = repo.DeleteExpired(context.Background(), time.Now())
	if err != nil {
		t.Errorf("failed to delete expired IP records: %v", err)
	}

	record, err := repo.GetByIp(context.Background(), "127.0.0.1")
	if err == nil {
		t.Errorf("there should be an error but got nil")
	}
	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}
	record, err = repo.GetByIp(context.Background(), "127.0.0.2")
	if err == nil {
		t.Errorf("there should be an error but got nil")
	}
	if record != nil {
		t.Errorf("expected record to be nil but got %v", record)
	}
}

func TestIPRepositoryFailToDelete(t *testing.T) {
	repo, db := initialize(t)
	db.Close()

	err := repo.Delete(context.Background(), "127.0.0.1")
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryDeleteExpiredWithNoRecords(t *testing.T) {
	repo, db := initialize(t)
	defer db.Close()

	err := repo.DeleteExpired(context.Background(), time.Now())
	if err != nil {
		t.Errorf("failed to delete expired IP records: %v", err)
	}
}

func TestIPRepositoryDeleteExpiredFailed(t *testing.T) {
	repo, db := initialize(t)
	db.Close()

	err := repo.DeleteExpired(context.Background(), time.Now())
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestIPRepositoryCount(t *testing.T) {
	repo, db := initialize(t)
	defer db.Close()

	// Initial count should be 0
	count, err := repo.Count(context.Background())
	if err != nil {
		t.Fatalf("expected no error from Count(), got %v", err)
	}
	if count != 0 {
		t.Errorf("expected count to be 0, got %d", count)
	}

	threatCount, err := repo.ThreatCount(context.Background())
	if err != nil {
		t.Fatalf("expected no error from ThreatCount(), got %v", err)
	}
	if threatCount != 0 {
		t.Errorf("expected threatCount to be 0, got %d", threatCount)
	}

	// Insert a threat record
	_, err = repo.Update(context.Background(), &model.IPRecord{IP: "1.2.3.4", Status: "threat", Score: 95, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	// Insert a safe record
	_, err = repo.Update(context.Background(), &model.IPRecord{IP: "1.2.3.5", Status: "safe", Score: 10, Source: "test", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	count, err = repo.Count(context.Background())
	if err != nil {
		t.Fatalf("expected no error from Count(), got %v", err)
	}
	if count != 2 {
		t.Errorf("expected count to be 2, got %d", count)
	}

	threatCount, err = repo.ThreatCount(context.Background())
	if err != nil {
		t.Fatalf("expected no error from ThreatCount(), got %v", err)
	}
	if threatCount != 1 {
		t.Errorf("expected threatCount to be 1, got %d", threatCount)
	}
}

func TestIPRepositoryCountFailed(t *testing.T) {
	repo, db := initialize(t)
	db.Close()

	_, err := repo.Count(context.Background())
	if err == nil {
		t.Error("expected error from Count() when database is closed, got nil")
	}
}

func initialize(t *testing.T) (*IPRepository, *sql.DB) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	db, err := OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// run migrations
	if err := RunMigrations(db, "../../db/migrations"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	cfg := &config.Config{}
	cfg.AbuseIPDB.Enabled = true
	cfg.AbuseIPDB.APIKey = "test"
	cfg.AbuseIPDB.ExpirationTime = 24 * time.Hour
	cfg.AbuseIPDB.ConfidenceScoreThreshold = 50
	repo := NewIPRepository(db, cfg)
	return repo, db
}

func TestIPRepositoryGetRecord(t *testing.T) {
	repo, db := initialize(t)
	defer db.Close()

	// Insert an expired record
	expiredAt := time.Now().Add(-1 * time.Hour)
	_, err := repo.db.Exec(`INSERT INTO ip_records VALUES (?, ?, ?, ?, ?, ?, ?)`, "10.0.0.1", "threat", 95, "test", time.Now(), expiredAt, 0)
	if err != nil {
		t.Fatalf("failed to insert test record: %v", err)
	}

	// GetByIp should return sql.ErrNoRows because it is expired
	_, err = repo.GetByIp(context.Background(), "10.0.0.1")
	if err != sql.ErrNoRows {
		t.Errorf("expected ErrNoRows, got: %v", err)
	}

	// GetRecord should return the record even though it is expired
	record, err := repo.GetRecord(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("expected no error from GetRecord, got: %v", err)
	}
	if record.IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got: %s", record.IP)
	}
	if record.Status != "threat" {
		t.Errorf("expected status 'threat', got: %s", record.Status)
	}
}

func TestIPRepositoryErrors(t *testing.T) {
	repo, db := initialize(t)
	db.Close()

	_, err := repo.GetByIp(context.Background(), "127.0.0.1")
	if err == nil {
		t.Error("expected error from GetByIp when database is closed, got nil")
	}

	_, err = repo.GetRecord(context.Background(), "127.0.0.1")
	if err == nil {
		t.Error("expected error from GetRecord when database is closed, got nil")
	}

	_, err = repo.ThreatCount(context.Background())
	if err == nil {
		t.Error("expected error from ThreatCount when database is closed, got nil")
	}
}

func TestIPRepositoryListRecords(t *testing.T) {
	repo, db := initialize(t)
	defer db.Close()

	now := time.Now()
	records := []model.IPRecord{
		{IP: "192.168.1.1", Status: "safe", Score: 5, Source: "local", CheckedAt: now, ExpiresAt: now.Add(1 * time.Hour), Reported: false},
		{IP: "192.168.1.2", Status: "threat", Score: 85, Source: "abuseipdb", CheckedAt: now, ExpiresAt: now.Add(2 * time.Hour), Reported: true},
		{IP: "10.0.0.1", Status: "threat", Score: 95, Source: "abuseipdb", CheckedAt: now, ExpiresAt: now.Add(3 * time.Hour), Reported: false},
	}

	for _, rec := range records {
		_, err := repo.Update(context.Background(), &rec)
		if err != nil {
			t.Fatalf("failed to insert record: %v", err)
		}
	}

	// Test case 1: List all
	res, total, err := repo.ListRecords(context.Background(), 10, 0, "", "", "expires_at", "DESC")
	if err != nil {
		t.Fatalf("ListRecords failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 records, got %d", total)
	}
	if len(res) != 3 {
		t.Errorf("expected 3 records returned, got %d", len(res))
	}
	// order should be 10.0.0.1, 192.168.1.2, 192.168.1.1 (based on expires_at DESC)
	if res[0].IP != "10.0.0.1" || res[2].IP != "192.168.1.1" {
		t.Errorf("incorrect ordering for expires_at DESC")
	}

	// Test case 2: Search by IP
	res, total, err = repo.ListRecords(context.Background(), 10, 0, "192.168", "", "ip", "ASC")
	if err != nil {
		t.Fatalf("ListRecords search failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 records matching '192.168', got %d", total)
	}
	if res[0].IP != "192.168.1.1" || res[1].IP != "192.168.1.2" {
		t.Errorf("incorrect search ordering or results")
	}

	// Test case 3: Pagination (limit/offset)
	res, total, err = repo.ListRecords(context.Background(), 1, 1, "", "", "score", "ASC")
	if err != nil {
		t.Fatalf("ListRecords pagination failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected total count to be 3, got %d", total)
	}
	if len(res) != 1 {
		t.Errorf("expected 1 record returned, got %d", len(res))
	}
	// scores in ASC order: 5 (192.168.1.1), 85 (192.168.1.2), 95 (10.0.0.1). Offset 1 should return 192.168.1.2.
	if res[0].IP != "192.168.1.2" {
		t.Errorf("expected 192.168.1.2 at offset 1, got %s", res[0].IP)
	}

	// Test case 4: Filter by Status
	res, total, err = repo.ListRecords(context.Background(), 10, 0, "", "threat", "ip", "ASC")
	if err != nil {
		t.Fatalf("ListRecords status filter failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 records with status 'threat', got %d", total)
	}
	if len(res) != 2 {
		t.Errorf("expected 2 records returned, got %d", len(res))
	}
	if res[0].IP != "10.0.0.1" || res[1].IP != "192.168.1.2" {
		t.Errorf("incorrect status filter results")
	}

	// Test case 5: Sort by Reported status
	res, total, err = repo.ListRecords(context.Background(), 10, 0, "", "", "reported", "DESC")
	if err != nil {
		t.Fatalf("ListRecords reported sort failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 records, got %d", total)
	}
	if res[0].IP != "192.168.1.2" {
		t.Errorf("expected 192.168.1.2 to be first when sorting by reported DESC, got %s", res[0].IP)
	}
}
