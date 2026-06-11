package activedefence

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skoczo/repgate/internal/abuseipdb"
	"github.com/skoczo/repgate/internal/model"
)

type mockDatabase struct {
	records map[string]*model.IPRecord
	update  func(record *model.IPRecord) (*model.IPRecord, error)
}

func (m *mockDatabase) Update(ctx context.Context, record *model.IPRecord) (*model.IPRecord, error) {
	if m.update != nil {
		return m.update(record)
	}
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

func TestParseExpirationTime(t *testing.T) {
	tests := []struct {
		input       string
		expDur      time.Duration
		isPermanent bool
		expectErr   bool
	}{
		{"permanent", 0, true, false},
		{"24h", 24 * time.Hour, false, false},
		{"12", 12 * time.Hour, false, false},
		{"invalid", 0, false, true},
		{"-5", 0, false, true},
	}

	for _, tc := range tests {
		dur, perm, err := parseExpirationTime(tc.input)
		if tc.expectErr {
			if err == nil {
				t.Errorf("expected error for input %q, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for input %q: %v", tc.input, err)
			}
			if perm != tc.isPermanent {
				t.Errorf("expected permanent=%v for input %q, got %v", tc.isPermanent, tc.input, perm)
			}
			if !perm && dur != tc.expDur {
				t.Errorf("expected duration=%s for input %q, got %s", tc.expDur, tc.input, dur)
			}
		}
	}
}

func TestIsHoneytoken(t *testing.T) {
	patterns := []string{
		"\\.env",
		"\\.git/",
		"wp-login\\.php",
		"(credentials|service-account)\\.json$",
	}

	svc, err := NewService(&mockDatabase{}, nil, "24h", patterns)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/.env", true},
		{"/backend/.env?foo=bar", true},
		{"/.git/config", true},
		{"/wp-login.php", true},
		{"/credentials.json", true},
		{"/sub/service-account.json", true},
		{"/robots.txt", false},
		{"/health", false},
		{"/sitemap.xml", false},
	}

	for _, tc := range tests {
		got := svc.IsHoneytoken(tc.path)
		if got != tc.expected {
			t.Errorf("IsHoneytoken(%q) = %v; expected %v", tc.path, got, tc.expected)
		}
	}
}

func TestReportThreat(t *testing.T) {
	db := &mockDatabase{records: make(map[string]*model.IPRecord)}
	cache := &mockCache{records: make(map[string]model.IPRecord)}

	svc, err := NewService(db, []Cache{cache}, "permanent", []string{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ip := "1.2.3.4"
	err = svc.ReportThreat(context.Background(), ip, "/.env")
	if err != nil {
		t.Fatalf("unexpected error reporting threat: %v", err)
	}

	// Verify DB write
	dbRec, err := db.GetRecord(context.Background(), ip)
	if err != nil {
		t.Fatalf("failed to get DB record: %v", err)
	}
	if dbRec.IP != ip || dbRec.Status != "threat" || dbRec.Score != 100 || dbRec.Source != "ActiveDefence" {
		t.Errorf("invalid record saved to DB: %+v", dbRec)
	}
	if dbRec.ExpiresAt.Year() != 9999 {
		t.Errorf("expected permanent expiration (year 9999), got: %v", dbRec.ExpiresAt)
	}

	// Verify Cache write
	cacheRec, ok := cache.records[ip]
	if !ok {
		t.Fatalf("IP not found in cache")
	}
	if cacheRec.IP != ip || cacheRec.Status != "threat" || cacheRec.Score != 100 || cacheRec.Source != "ActiveDefence" {
		t.Errorf("invalid record saved to cache: %+v", cacheRec)
	}
}

func TestReportThreat_AutoReport(t *testing.T) {
	db := &mockDatabase{records: make(map[string]*model.IPRecord)}
	cache := &mockCache{records: make(map[string]model.IPRecord)}

	svc, err := NewService(db, []Cache{cache}, "permanent", []string{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	// Setup a mock server for AbuseIPDB
	reported := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			reported <- true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Initialize the singleton client pointing to the test server
	client := abuseipdb.NewAbuseIPDBRestClient("test-key")
	client.AbuseIPDBRestReportUrl = server.URL
	abuseipdb.SetClient(client)

	// Enable auto report
	svc.SetAutoReport(true, []int{21}, "test-comment")

	ip := "1.2.3.4"
	err = svc.ReportThreat(context.Background(), ip, "/.env")
	if err != nil {
		t.Fatalf("unexpected error reporting threat: %v", err)
	}

	// Since reporting is done in a goroutine, wait for it
	select {
	case <-reported:
		// success
	case <-time.After(1 * time.Second):
		t.Error("timeout waiting for AbuseIPDB report call")
	}
}
