package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/api/handlers"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/event"
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
func (m *mockThreatSource) Check(ctx context.Context, req threatcheck.CheckContext) (threatcheck.ThreatCheckResult, error) {
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
			router := NewRouter(tt.threatSources, nil, tt.failOpen, false, 5*time.Second, event.NewService(nil, 7), nil)

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

	router := NewRouter([]threatcheck.ThreatSource{adService}, adService, false, false, 5*time.Second, event.NewService(nil, 7), nil)

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

	router := NewRouter([]threatcheck.ThreatSource{adService}, adService, false, false, 5*time.Second, event.NewService(nil, 7), nil)

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
	router := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(eventRepo, 7), nil)

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
	router := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(nil, 0), nil)

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

func TestHandler_eventsFiltering(t *testing.T) {
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
	router := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(eventRepo, 7), nil)

	// Insert test events
	err = eventRepo.Insert(context.Background(), &model.Event{
		IP:         "1.1.1.1",
		TargetHost: "example.com",
		TargetPath: "/home",
		Action:     "allow",
		Source:     "System",
		Timestamp:  time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to insert allow event: %v", err)
	}

	err = eventRepo.Insert(context.Background(), &model.Event{
		IP:         "2.2.2.2",
		TargetHost: "example.com",
		TargetPath: "/admin",
		Action:     "block",
		Source:     "AbuseIPDB",
		Timestamp:  time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to insert block event: %v", err)
	}

	// 1. Query only blocked events
	reqBlock := httptest.NewRequest("GET", "/api/v1/events?limit=10&action=block", nil)
	rrBlock := httptest.NewRecorder()
	router.ServeHTTP(rrBlock, reqBlock)

	if rrBlock.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rrBlock.Code)
	}

	var blockedEvents []model.Event
	if err := json.Unmarshal(rrBlock.Body.Bytes(), &blockedEvents); err != nil {
		t.Fatalf("failed to unmarshal blocked events: %v", err)
	}

	if len(blockedEvents) != 1 {
		t.Fatalf("expected 1 blocked event, got %d", len(blockedEvents))
	}
	if blockedEvents[0].IP != "2.2.2.2" {
		t.Errorf("expected IP to be 2.2.2.2, got %s", blockedEvents[0].IP)
	}

	// 2. Query only allowed events
	reqAllow := httptest.NewRequest("GET", "/api/v1/events?limit=10&action=allow", nil)
	rrAllow := httptest.NewRecorder()
	router.ServeHTTP(rrAllow, reqAllow)

	if rrAllow.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rrAllow.Code)
	}

	var allowedEvents []model.Event
	if err := json.Unmarshal(rrAllow.Body.Bytes(), &allowedEvents); err != nil {
		t.Fatalf("failed to unmarshal allowed events: %v", err)
	}

	if len(allowedEvents) != 1 {
		t.Fatalf("expected 1 allowed event, got %d", len(allowedEvents))
	}
	if allowedEvents[0].IP != "1.1.1.1" {
		t.Errorf("expected IP to be 1.1.1.1, got %s", allowedEvents[0].IP)
	}

	// 3. Query all events (invalid action query should default to all)
	reqAll := httptest.NewRequest("GET", "/api/v1/events?limit=10&action=invalid", nil)
	rrAll := httptest.NewRecorder()
	router.ServeHTTP(rrAll, reqAll)

	if rrAll.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rrAll.Code)
	}

	var allEvents []model.Event
	if err := json.Unmarshal(rrAll.Body.Bytes(), &allEvents); err != nil {
		t.Fatalf("failed to unmarshal all events: %v", err)
	}

	if len(allEvents) != 2 {
		t.Fatalf("expected 2 events, got %d", len(allEvents))
	}
}

func TestHandler_getTargetHost(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		host     string
		expected string
	}{
		{
			name:     "X-Real-Target",
			headers:  map[string]string{"X-Real-Target": "real-target.com"},
			host:     "default.com",
			expected: "real-target.com",
		},
		{
			name:     "X-Forwarded-Host",
			headers:  map[string]string{"X-Forwarded-Host": "forwarded.com"},
			host:     "default.com",
			expected: "forwarded.com",
		},
		{
			name:     "X-Original-Host",
			headers:  map[string]string{"X-Original-Host": "original.com"},
			host:     "default.com",
			expected: "original.com",
		},
		{
			name:     "Host header default",
			headers:  map[string]string{},
			host:     "default.com",
			expected: "default.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/check", nil)
			req.Host = tt.host
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := handlers.GetTargetHost(req)
			if got != tt.expected {
				t.Errorf("getTargetHost() = %s; expected %s", got, tt.expected)
			}
		})
	}
}

type errorDatabase struct{}

func (e *errorDatabase) Update(ctx context.Context, record *model.IPRecord) (*model.IPRecord, error) {
	return nil, errors.New("db error")
}
func (e *errorDatabase) GetRecord(ctx context.Context, ip string) (*model.IPRecord, error) {
	return nil, errors.New("db error")
}

func TestHandler_checkHandler_AD_Error(t *testing.T) {
	db := &errorDatabase{}
	adService, err := activedefence.NewService(db, nil, "24h", []string{"\\.env"})
	if err != nil {
		t.Fatalf("failed to create adService: %v", err)
	}

	router := NewRouter([]threatcheck.ThreatSource{adService}, adService, false, true, 5*time.Second, event.NewService(nil, 7), nil)

	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Client-IP", "1.1.1.1")
	req.Header.Set("X-Original-URI", "/.env")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestHandler_statusHandler(t *testing.T) {
	router := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(nil, 7), nil)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var status model.SystemStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to unmarshal status: %v", err)
	}

	if status.LiveStreamRetentionDays != 7 {
		t.Errorf("expected retention days 7, got %d", status.LiveStreamRetentionDays)
	}
}

func TestHandler_reportThreatHandler_Errors(t *testing.T) {
	routerNoAD := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(nil, 7), nil)
	req := httptest.NewRequest("POST", "/report-threat", nil)
	rr := httptest.NewRecorder()
	routerNoAD.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when AD is disabled, got %d", rr.Code)
	}

	db := &mockDatabase{records: make(map[string]*model.IPRecord)}
	adService, _ := activedefence.NewService(db, nil, "24h", []string{})
	router := NewRouter([]threatcheck.ThreatSource{adService}, adService, false, false, 5*time.Second, event.NewService(nil, 7), nil)

	reqRemote := httptest.NewRequest("POST", "/report-threat", nil)
	reqRemote.RemoteAddr = "invalid-ip-port"
	rrRemote := httptest.NewRecorder()
	router.ServeHTTP(rrRemote, reqRemote)
	if rrRemote.Code != http.StatusBadRequest {
		t.Errorf("expected 400 with invalid remote addr, got %d", rrRemote.Code)
	}

	reqRemoteValid := httptest.NewRequest("POST", "/report-threat", nil)
	reqRemoteValid.RemoteAddr = "1.2.3.4:1234"
	rrRemoteValid := httptest.NewRecorder()
	router.ServeHTTP(rrRemoteValid, reqRemoteValid)
	if rrRemoteValid.Code != http.StatusOK {
		t.Errorf("expected 200 with valid RemoteAddr, got %d", rrRemoteValid.Code)
	}

	dbError := &errorDatabase{}
	adServiceErr, _ := activedefence.NewService(dbError, nil, "24h", []string{})
	routerErr := NewRouter([]threatcheck.ThreatSource{adServiceErr}, adServiceErr, false, false, 5*time.Second, event.NewService(nil, 7), nil)
	reqErr := httptest.NewRequest("POST", "/report-threat", nil)
	reqErr.Header.Set("X-Client-IP", "1.1.1.1")
	rrErr := httptest.NewRecorder()
	routerErr.ServeHTTP(rrErr, reqErr)
	if rrErr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ReportThreat fails, got %d", rrErr.Code)
	}
}

func TestHandler_eventsHandler_Params(t *testing.T) {
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
	router := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(eventRepo, 7), nil)

	eventRepo.Insert(context.Background(), &model.Event{
		IP: "1.1.1.1", Action: "allow", Source: "System", Timestamp: time.Now(),
	})

	reqLimitInvalid := httptest.NewRequest("GET", "/api/v1/events?limit=invalid", nil)
	rrLimitInvalid := httptest.NewRecorder()
	router.ServeHTTP(rrLimitInvalid, reqLimitInvalid)
	if rrLimitInvalid.Code != http.StatusOK {
		t.Errorf("expected 200 with invalid limit, got %d", rrLimitInvalid.Code)
	}

	reqLimitHigh := httptest.NewRequest("GET", "/api/v1/events?limit=200", nil)
	rrLimitHigh := httptest.NewRecorder()
	router.ServeHTTP(rrLimitHigh, reqLimitHigh)
	if rrLimitHigh.Code != http.StatusOK {
		t.Errorf("expected 200 with high limit, got %d", rrLimitHigh.Code)
	}

	reqBeforeID := httptest.NewRequest("GET", "/api/v1/events?before_id=10", nil)
	rrBeforeID := httptest.NewRecorder()
	router.ServeHTTP(rrBeforeID, reqBeforeID)
	if rrBeforeID.Code != http.StatusOK {
		t.Errorf("expected 200 with before_id, got %d", rrBeforeID.Code)
	}

	routerNoRepo := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(nil, 7), nil)
	reqNoRepo := httptest.NewRequest("GET", "/api/v1/events", nil)
	rrNoRepo := httptest.NewRecorder()
	routerNoRepo.ServeHTTP(rrNoRepo, reqNoRepo)
	if rrNoRepo.Code != http.StatusOK {
		t.Errorf("expected 200 when eventRepo is nil, got %d", rrNoRepo.Code)
	}

	dbConn.Close()
	reqDBErr := httptest.NewRequest("GET", "/api/v1/events", nil)
	rrDBErr := httptest.NewRecorder()
	router.ServeHTTP(rrDBErr, reqDBErr)
	if rrDBErr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on db query error, got %d", rrDBErr.Code)
	}
}

func TestHandler_streamLogsHandler_Streaming(t *testing.T) {
	eventService := event.NewService(nil, 7)
	handler := handlers.NewHandler(nil, nil, false, false, eventService, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/stream/logs", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.StreamLogsHandler(rr, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	eventService.Publish("10.10.10.10", "host.com", "/path", "block", "System")

	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	if rr.Code != http.StatusOK {
		t.Errorf("expected stream code 200, got %d", rr.Code)
	}
	bodyStr := rr.Body.String()
	if !strings.Contains(bodyStr, "10.10.10.10") {
		t.Errorf("expected event in stream, body: %q", bodyStr)
	}
}

func TestHandler_staticRoutes(t *testing.T) {
	router := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(nil, 7), nil)

	reqIndex := httptest.NewRequest("GET", "/", nil)
	rrIndex := httptest.NewRecorder()
	router.ServeHTTP(rrIndex, reqIndex)

	req404 := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
	rr404 := httptest.NewRecorder()
	router.ServeHTTP(rr404, req404)
	if rr404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent API route, got %d", rr404.Code)
	}
}

func TestHandler_dbRecordsHandler(t *testing.T) {
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

	cfg := &config.Config{}
	cfg.AbuseIPDB.ExpirationTime = 24 * time.Hour
	ipRepo := storage.NewIPRepository(dbConn, cfg)

	router := NewRouter(nil, nil, false, false, 5*time.Second, event.NewService(nil, 7), ipRepo)

	// Insert test data
	now := time.Now()
	_, err = ipRepo.Update(context.Background(), &model.IPRecord{IP: "1.1.1.1", Status: "threat", Score: 90, Source: "abuseipdb", CheckedAt: now, ExpiresAt: now.Add(1 * time.Hour)})
	if err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/db/records?limit=10&sort_by=ip&sort_order=asc", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var res struct {
		Records []model.IPRecord `json:"records"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if res.Total != 1 {
		t.Errorf("expected total 1, got %d", res.Total)
	}
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(res.Records))
	}
	if res.Records[0].IP != "1.1.1.1" {
		t.Errorf("expected IP 1.1.1.1, got %s", res.Records[0].IP)
	}

	// Test status filter via API
	reqStatus := httptest.NewRequest("GET", "/api/v1/db/records?status=threat", nil)
	rrStatus := httptest.NewRecorder()
	router.ServeHTTP(rrStatus, reqStatus)

	if rrStatus.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rrStatus.Code)
	}

	var resStatus struct {
		Records []model.IPRecord `json:"records"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(rrStatus.Body.Bytes(), &resStatus); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resStatus.Total != 1 {
		t.Errorf("expected total 1 with status filter, got %d", resStatus.Total)
	}
	if len(resStatus.Records) != 1 {
		t.Fatalf("expected 1 record with status filter, got %d", len(resStatus.Records))
	}
}
