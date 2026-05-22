package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/metrics"
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
func (m *mockThreatSource) CheckIP(ip string) (threatcheck.ThreatCheckResult, error) {
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
			router := NewRouter(tt.threatSources, tt.failOpen, 5*time.Second)

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
