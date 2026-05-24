//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/skoczo/repgate/internal/abuseipdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_AbuseIPDBRestClient(t *testing.T) {
	token := os.Getenv("ABUSEIPDB_TOKEN")
	if token == "" {
		t.Skip("Skipping integration test: ABUSEIPDB_TOKEN environment variable not set")
	}

	client := abuseipdb.NewAbuseIPDBRestClient(token)

	// Test against a known safe public IP (Google DNS)
	ip := "8.8.8.8"

	score, err := client.CheckIP(context.Background(), ip)

	require.NoError(t, err, "Expected no error when calling real AbuseIPDB API")
	// Google DNS should have an extremely low, or 0, abuse confidence score
	assert.LessOrEqual(t, score, 10, "Expected low abuse score for Google DNS")

	// test against thread ip
	ip = "1.2.3.4"

	score, err = client.CheckIP(context.Background(), ip)
	require.NoError(t, err, "Expected no error when calling real AbuseIPDB API")
	assert.Greater(t, score, 10, "Expected high abuse score for thread IP")
}
