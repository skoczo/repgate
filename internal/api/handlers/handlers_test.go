package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/event"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/threatcheck"
)

type mockThreatSource struct {
	name    string
	enabled bool
	result  threatcheck.ThreatCheckResult
	err     error
}

func (m *mockThreatSource) Name() string  { return m.name }
func (m *mockThreatSource) Enabled() bool { return m.enabled }
func (m *mockThreatSource) Check(ctx context.Context, req threatcheck.CheckContext) (threatcheck.ThreatCheckResult, error) {
	return m.result, m.err
}
func (m *mockThreatSource) CleanExpired(now time.Time) {}
func (m *mockThreatSource) SetMetrics(metrics *metrics.Metrics) {}

type mockDB struct {
	records map[string]*model.IPRecord
	err     error
}

func (m *mockDB) Update(ctx context.Context, record *model.IPRecord) (*model.IPRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.records[record.IP] = record
	return record, nil
}

func (m *mockDB) GetRecord(ctx context.Context, ip string) (*model.IPRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
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

func TestHandler_NewHandler_ParseError(t *testing.T) {
	// Passing invalid local network string triggers slog.Error in NewHandler
	h := NewHandler(nil, nil, false, false, nil, nil, []string{"invalid-cidr/999"})
	if len(h.LocalNetworks) != 0 {
		t.Errorf("expected 0 local networks on parse error, got %d", len(h.LocalNetworks))
	}
}

func TestHandler_IsLocalIP(t *testing.T) {
	localNetworks := []string{
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"127.0.0.1",
		"::1",
	}

	h := NewHandler(nil, nil, false, false, nil, nil, localNetworks)

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.22", true},
		{"10.10.1.45", true},
		{"172.30.0.7", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"::ffff:192.168.1.22", true}, // IPv4-mapped IPv6 (tests addr.Unmap())
		{"8.8.8.8", false},
		{"172.32.0.1", false},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		addr, err := netip.ParseAddr(tt.ip)
		if err != nil {
			t.Fatalf("failed to parse IP %s: %v", tt.ip, err)
		}
		if got := h.IsLocalIP(addr); got != tt.expected {
			t.Errorf("IsLocalIP(%s) = %v, expected %v", tt.ip, got, tt.expected)
		}
	}
}

func TestCheckHandler_LocalNetworks(t *testing.T) {
	localNetworks := []string{
		"192.168.0.0/16",
		"10.0.0.0/8",
	}

	eventService := event.NewService(nil, 7)
	ch := eventService.Subscribe()
	defer eventService.Unsubscribe(ch)

	// Mock source that flags threats
	threatSource := &mockThreatSource{
		name:    "MockThreat",
		enabled: true,
		result:  threatcheck.ThreatCheckResult{IsThreat: true, Source: "MockThreat"},
	}

	// Test with LogSafeIPs = true
	hWithLog := NewHandler([]threatcheck.ThreatSource{threatSource}, nil, false, true, eventService, nil, localNetworks)

	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Client-IP", "192.168.1.22")
	rr := httptest.NewRecorder()
	hWithLog.CheckHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	select {
	case ev := <-ch:
		if ev.IP != "192.168.1.22" || ev.Source != "LocalNetwork" || ev.Action != "allow" {
			t.Errorf("unexpected event: %+v", ev)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for event")
	}

	// Test with LogSafeIPs = false
	hWithoutLog := NewHandler([]threatcheck.ThreatSource{threatSource}, nil, false, false, eventService, nil, localNetworks)

	reqNoLog := httptest.NewRequest("GET", "/check", nil)
	reqNoLog.Header.Set("X-Client-IP", "10.0.0.5")
	rrNoLog := httptest.NewRecorder()
	hWithoutLog.CheckHandler(rrNoLog, reqNoLog)

	if rrNoLog.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rrNoLog.Code)
	}
}

func TestCheckHandler_Validations(t *testing.T) {
	h := NewHandler(nil, nil, false, false, nil, nil, nil)

	// Missing X-Client-IP
	reqMissing := httptest.NewRequest("GET", "/check", nil)
	rrMissing := httptest.NewRecorder()
	h.CheckHandler(rrMissing, reqMissing)
	if rrMissing.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for missing IP, got %d", rrMissing.Code)
	}

	// Invalid X-Client-IP
	reqInvalid := httptest.NewRequest("GET", "/check", nil)
	reqInvalid.Header.Set("X-Client-IP", "not-an-ip")
	rrInvalid := httptest.NewRecorder()
	h.CheckHandler(rrInvalid, reqInvalid)
	if rrInvalid.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for invalid IP, got %d", rrInvalid.Code)
	}
}

func TestReportThreatHandler_LocalNetworks(t *testing.T) {
	db := &mockDB{records: make(map[string]*model.IPRecord)}
	cache := &mockCache{records: make(map[string]model.IPRecord)}
	adService, err := activedefence.NewService(db, []activedefence.Cache{cache}, nil, "24h", []string{})
	if err != nil {
		t.Fatalf("failed to create adService: %v", err)
	}

	localNetworks := []string{"192.168.0.0/16"}
	h := NewHandler(nil, adService, false, false, nil, nil, localNetworks)

	// Local IP should be ignored and not recorded
	reqLocal := httptest.NewRequest("POST", "/report-threat", nil)
	reqLocal.Header.Set("X-Client-IP", "192.168.1.100")
	rrLocal := httptest.NewRecorder()
	h.ReportThreatHandler(rrLocal, reqLocal)

	if rrLocal.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rrLocal.Code)
	}
	var res map[string]string
	if err := json.Unmarshal(rrLocal.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if res["status"] != "ignored" {
		t.Errorf("expected status 'ignored', got %q", res["status"])
	}
	if _, ok := cache.records["192.168.1.100"]; ok {
		t.Error("local IP was unexpectedly recorded in cache")
	}

	// Non-local IP should be reported
	reqExternal := httptest.NewRequest("POST", "/report-threat", nil)
	reqExternal.Header.Set("X-Client-IP", "203.0.113.10")
	rrExternal := httptest.NewRecorder()
	h.ReportThreatHandler(rrExternal, reqExternal)

	if rrExternal.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rrExternal.Code)
	}
	if _, ok := cache.records["203.0.113.10"]; !ok {
		t.Error("external IP was not recorded in cache")
	}

	// Invalid IP in report threat
	reqInvalid := httptest.NewRequest("POST", "/report-threat", nil)
	reqInvalid.Header.Set("X-Client-IP", "invalid-ip")
	rrInvalid := httptest.NewRecorder()
	h.ReportThreatHandler(rrInvalid, reqInvalid)
	if rrInvalid.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid IP, got %d", rrInvalid.Code)
	}

	// AD service disabled (nil)
	hNoAD := NewHandler(nil, nil, false, false, nil, nil, localNetworks)
	reqNoAD := httptest.NewRequest("POST", "/report-threat", nil)
	rrNoAD := httptest.NewRecorder()
	hNoAD.ReportThreatHandler(rrNoAD, reqNoAD)
	if rrNoAD.Code != http.StatusNotFound {
		t.Errorf("expected 404 when AD is disabled, got %d", rrNoAD.Code)
	}

	// AD report error
	dbErr := &mockDB{records: make(map[string]*model.IPRecord), err: errors.New("db write failed")}
	adServiceErr, _ := activedefence.NewService(dbErr, nil, nil, "24h", []string{})
	hErr := NewHandler(nil, adServiceErr, false, false, nil, nil, localNetworks)
	reqErr := httptest.NewRequest("POST", "/report-threat", nil)
	reqErr.Header.Set("X-Client-IP", "203.0.113.20")
	rrErr := httptest.NewRecorder()
	hErr.ReportThreatHandler(rrErr, reqErr)
	if rrErr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when report fails, got %d", rrErr.Code)
	}
}
