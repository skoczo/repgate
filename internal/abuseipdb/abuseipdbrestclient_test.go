package abuseipdb

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAbuseIPDBRestClient_CheckIP(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseBody   string
		expectedScore  int
		expectError    bool
	}{
		{
			name:           "success",
			responseStatus: http.StatusOK,
			responseBody:   `{"data":{"abuseConfidenceScore": 85}}`,
			expectedScore:  85,
			expectError:    false,
		},
		{
			name:           "api error",
			responseStatus: http.StatusForbidden,
			responseBody:   `{}`,
			expectedScore:  0,
			expectError:    true,
		},
		{
			name:           "invalid json",
			responseStatus: http.StatusOK,
			responseBody:   `invalid`,
			expectedScore:  0,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Key") != "test-key" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(tt.responseStatus)
				fmt.Fprint(w, tt.responseBody)
			}))
			defer server.Close()

			client := NewAbuseIPDBRestClient("test-key")
			client.AbuseIPDBRestCheckUrl = server.URL + "?ipAddress=%s&maxAgeInDays=90"

			score, err := client.CheckIP(context.Background(), "127.0.0.1")

			if (err != nil) != tt.expectError {
				t.Fatalf("expected error: %v, got: %v", tt.expectError, err)
			}

			if score != tt.expectedScore {
				t.Errorf("expected score: %d, got: %d", tt.expectedScore, score)
			}
		})
	}
}

func TestAbuseIPDBRestClient_Errors(t *testing.T) {
	// 1. url.Parse error
	client := NewAbuseIPDBRestClient("test-key")
	client.AbuseIPDBRestCheckUrl = "%%invalid-url"
	_, err := client.CheckIP(context.Background(), "127.0.0.1")
	if err == nil {
		t.Error("expected error with invalid URL")
	}

	// 2. HTTPClient.Do error
	client2 := NewAbuseIPDBRestClient("test-key")
	client2.AbuseIPDBRestCheckUrl = "http://127.0.0.1:9999/check?ip=%s"
	_, err = client2.CheckIP(context.Background(), "127.0.0.1")
	if err == nil {
		t.Error("expected error with connection refused")
	}

	// 3. context cancellation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"abuseConfidenceScore": 85}}`)
	}))
	defer server.Close()

	client3 := NewAbuseIPDBRestClient("test-key")
	client3.AbuseIPDBRestCheckUrl = server.URL + "?ipAddress=%s"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client3.CheckIP(ctx, "127.0.0.1")
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
