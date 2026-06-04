package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/storage"
	"github.com/skoczo/repgate/internal/threatcheck"
)

type mockThreatSource struct {
	name    string
	enabled bool
	result  threatcheck.ThreatCheckResult
	err     error

	metrics *metrics.Metrics
}

func (m *mockThreatSource) Name() string  { return m.name }
func (m *mockThreatSource) Enabled() bool { return m.enabled }
func (m *mockThreatSource) CheckIP(ctx context.Context, ip string) (threatcheck.ThreatCheckResult, error) {
	return m.result, m.err
}
func (m *mockThreatSource) CleanExpired(now time.Time) {}
func (m *mockThreatSource) SetMetrics(metrics *metrics.Metrics) {
	m.metrics = metrics
}

func TestHandler_checkHanlder(t *testing.T) {
	tests := []struct {
		name           string
		failOpen       bool
		threatSources  []threatcheck.ThreatSource
		expectedStatus int
	}{
		{
			name:     "no threat",
			failOpen: false,
			threatSources: []threatcheck.ThreatSource{
				&mockThreatSource{name: "Mock", enabled: true, result: threatcheck.ThreatCheckResult{IsThreat: false}},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "is threat",
			failOpen: false,
			threatSources: []threatcheck.ThreatSource{
				&mockThreatSource{name: "Mock", enabled: true, result: threatcheck.ThreatCheckResult{IsThreat: true}},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:     "disabled source",
			failOpen: false,
			threatSources: []threatcheck.ThreatSource{
				&mockThreatSource{name: "Mock", enabled: false},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "error fail open",
			failOpen: true,
			threatSources: []threatcheck.ThreatSource{
				&mockThreatSource{name: "Mock", enabled: true, err: errors.New("some error")},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "error fail closed",
			failOpen: false,
			threatSources: []threatcheck.ThreatSource{
				&mockThreatSource{name: "Mock", enabled: true, err: errors.New("some error")},
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:     "missing X-Client-IP",
			failOpen: false,
			threatSources: []threatcheck.ThreatSource{
				&mockThreatSource{name: "Mock", enabled: true},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:     "invalid X-Client-IP",
			failOpen: false,
			threatSources: []threatcheck.ThreatSource{
				&mockThreatSource{name: "Mock", enabled: true},
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(tt.threatSources, nil, tt.failOpen, false, 5*time.Second, nil, 7)

			req := httptest.NewRequest("GET", "/check", nil)
			if tt.name == "invalid X-Client-IP" {
				req.Header.Set("X-Client-IP", "invalid-ip")
			} else if tt.name != "missing X-Client-IP" {
				req.Header.Set("X-Client-IP", "127.0.0.1")
			}
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

type mockDatabase struct {
	records map[string]*model.IPRecord
}

func (m *mockDatabase) Update(ctx context.Context, record *model.IPRecord) (*model.IPRecord, error) {
	m.records[record.IP] = record
	return record, nil
}

func (m *mockDatabase) GetRecord(ctx context.Context, ip string) (*model.IPRecord, error) {
	if r, ok := m.records[ip]; ok {
		return r, nil
	}
	return nil, sql.ErrNoRows
}

type mockCache struct {
	records map[string]model.IPRecord
}

func (m *mockCache) Set(ip string, record model.IPRecord) {
	m.records[ip] = record
}

func TestHandler_honeytokenDetection(t *testing.T) {
	db := &mockDatabase{records: make(map[string]*model.IPRecord)}
	cache := &mockCache{records: make(map[string]model.IPRecord)}

	adService, err := activedefence.NewService(db, []activedefence.Cache{cache}, "permanent", []string{"\\.env"})
	if err != nil {
		t.Fatalf("failed to create adService: %v", err)
	}

	router := NewRouter(nil, adService, false, false, 5*time.Second, nil, 7)

	// Call check with a honeytoken path
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Client-IP", "1.2.3.4")
	req.Header.Set("X-Original-URI", "/.env")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}

	// Verify threat is saved in DB and Cache
	rec, ok := cache.records["1.2.3.4"]
	if !ok {
		t.Error("IP not found in cache")
	}
	if rec.Status != "threat" {
		t.Errorf("expected status 'threat', got %s", rec.Status)
	}
}

func TestHandler_reportThreatHandler(t *testing.T) {
	db := &mockDatabase{records: make(map[string]*model.IPRecord)}
	cache := &mockCache{records: make(map[string]model.IPRecord)}

	adService, err := activedefence.NewService(db, []activedefence.Cache{cache}, "permanent", []string{})
	if err != nil {
		t.Fatalf("failed to create adService: %v", err)
	}

	router := NewRouter(nil, adService, false, false, 5*time.Second, nil, 7)

	req := httptest.NewRequest("POST", "/report-threat", nil)
	req.Header.Set("X-Client-IP", "5.6.7.8")
	req.Header.Set("X-Original-URI", "/manual-report")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Verify threat is saved in DB and Cache
	rec, ok := cache.records["5.6.7.8"]
	if !ok {
		t.Error("IP not found in cache")
	}
	if rec.Status != "threat" {
		t.Errorf("expected status 'threat', got %s", rec.Status)
	}
}

func TestHandler_eventsAndStreaming(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "repgate.db")
	dbConn, err := storage.OpenSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer dbConn.Close()

	if err := storage.RunMigrations(dbConn, "../../db/migrations"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	eventRepo := storage.NewEventRepository(dbConn)
	router := NewRouter(nil, nil, false, false, 5*time.Second, eventRepo, 7)

	// Trigger a check request that logs an event
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Client-IP", "9.9.9.9")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Wait a brief moment for the async event processor to save the event to the DB
	time.Sleep(100 * time.Millisecond)

	// Query events history
	reqHist := httptest.NewRequest("GET", "/api/v1/events?limit=10", nil)
	rrHist := httptest.NewRecorder()
	router.ServeHTTP(rrHist, reqHist)

	if rrHist.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rrHist.Code)
	}

	var events []model.Event
	if err := json.Unmarshal(rrHist.Body.Bytes(), &events); err != nil {
		t.Fatalf("failed to unmarshal events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].IP != "9.9.9.9" {
		t.Errorf("expected event IP to be 9.9.9.9, got %s", events[0].IP)
	}
	if events[0].Action != "allow" {
		t.Errorf("expected event action to be allow, got %s", events[0].Action)
	}
}

func TestHandler_eventsDisabled(t *testing.T) {
	router := NewRouter(nil, nil, false, false, 5*time.Second, nil, 0)

	// Fetching events should return StatusForbidden
	reqHist := httptest.NewRequest("GET", "/api/v1/events", nil)
	rrHist := httptest.NewRecorder()
	router.ServeHTTP(rrHist, reqHist)

	if rrHist.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rrHist.Code)
	}

	// Fetching logs stream should return StatusForbidden
	reqStream := httptest.NewRequest("GET", "/api/v1/stream/logs", nil)
	rrStream := httptest.NewRecorder()
	router.ServeHTTP(rrStream, reqStream)

	if rrStream.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rrStream.Code)
	}
}
