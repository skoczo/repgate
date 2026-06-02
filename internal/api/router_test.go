package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
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
			router := NewRouter(tt.threatSources, nil, tt.failOpen, false, 5*time.Second)

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

	router := NewRouter(nil, adService, false, false, 5*time.Second)

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

	router := NewRouter(nil, adService, false, false, 5*time.Second)

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
