//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getBinaryPath locates the compiled repgate binary, or compiles it on the fly.
func getBinaryPath(t *testing.T) string {
	// Look for existing binary built by make/CI
	binPath := "../../bin/repgate"
	if _, err := os.Stat(binPath); err == nil {
		abspath, err := filepath.Abs(binPath)
		if err == nil {
			return abspath
		}
	}

	t.Log("repgate binary not found at ../../bin/repgate, compiling on the fly...")
	tempDir := t.TempDir()
	binPath = filepath.Join(tempDir, "repgate")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/repgate")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build repgate binary: %v", err)
	}
	return binPath
}

// getFreePort listens on a random port to avoid conflicts.
func getFreePort(t *testing.T) int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(t, err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// copyMigrations copies SQLite migrations from the project to the temp work directory.
func copyMigrations(t *testing.T, srcDir, destDir string) {
	err := os.MkdirAll(destDir, 0755)
	require.NoError(t, err)

	files, err := os.ReadDir(srcDir)
	require.NoError(t, err)

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, file.Name()))
		require.NoError(t, err)

		err = os.WriteFile(filepath.Join(destDir, file.Name()), data, 0644)
		require.NoError(t, err)
	}
}

func TestIntegration_ServerFlow(t *testing.T) {
	// 1. Locate/build binary
	binaryPath := getBinaryPath(t)

	// 2. Start mock AbuseIPDB server
	mockAbuseIPDB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "mock-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ip := r.URL.Query().Get("ipAddress")
		w.Header().Set("Content-Type", "application/json")

		switch ip {
		case "1.1.1.1":
			// Safe IP
			_, _ = w.Write([]byte(`{"data":{"ipAddress":"1.1.1.1","abuseConfidenceScore":0}}`))
		case "2.2.2.2":
			// Threat IP
			_, _ = w.Write([]byte(`{"data":{"ipAddress":"2.2.2.2","abuseConfidenceScore":100}}`))
		case "5.5.5.5":
			// Simulate error for circuit breaker
			w.WriteHeader(http.StatusInternalServerError)
		default:
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"ipAddress":"%s","abuseConfidenceScore":0}}`, ip)))
		}
	}))
	defer mockAbuseIPDB.Close()

	// 3. Create temp workspace directory for repgate subprocess
	tempDir := t.TempDir()

	// Copy migrations to tempDir/db/migrations
	copyMigrations(t, "../../db/migrations", filepath.Join(tempDir, "db", "migrations"))

	// Create data directory
	err := os.MkdirAll(filepath.Join(tempDir, "data"), 0755)
	require.NoError(t, err)

	// Get free port
	port := getFreePort(t)

	// Write config.yaml
	configContent := fmt.Sprintf(`
log_level: debug
log_safe_ips: true
live_stream_retention_days: 7
fail_open: true

server:
  port: ":%d"
  read_timeout: 5s
  write_timeout: 10s
  read_header_timeout: 2s

AbuseIPDB:
  enabled: true
  api_key: "mock-api-key"
  api_url: "%s/?ipAddress=%%s"
  expiration_time: 10s
  confidence_score_threshold: 50
  cache_max_size: 100
  circuit_breaker:
    max_retries: 2
    cool_down_period: 2s
    open_on_error: true

active_defence:
  enabled: true
  expiration_time: "permanent"
  honeytoken_paths:
    - '\.env'
    - 'wp-login\.php'
`, port, mockAbuseIPDB.URL)

	err = os.WriteFile(filepath.Join(tempDir, "config.yaml"), []byte(configContent), 0644)
	require.NoError(t, err)

	// 4. Start the repgate server subprocess
	cmd := exec.Command(binaryPath, "-c", "config.yaml")
	cmd.Dir = tempDir

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	err = cmd.Start()
	require.NoError(t, err)

	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// 5. Wait for server to start
	serverAddr := fmt.Sprintf("http://localhost:%d", port)
	statusURL := fmt.Sprintf("%s/api/v1/status", serverAddr)
	checkURL := fmt.Sprintf("%s/check", serverAddr)

	var isUp bool
	for i := 0; i < 30; i++ {
		resp, err := http.Get(statusURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				isUp = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, isUp, "Server failed to start in time. Stdout: %s\nStderr: %s", stdoutBuf.String(), stderrBuf.String())

	// 6. Run scenarios

	// Scenario A: Request without X-Client-IP header -> expects 403 Forbidden
	t.Run("Missing X-Client-IP header", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Scenario A.2: Request with invalid X-Client-IP format -> expects 403 Forbidden
	t.Run("Invalid X-Client-IP format", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "invalid-ip-format")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Scenario A.3 & E.2: Request with custom host and path metadata, then query via API
	t.Run("Original Host & URI Metadata logging and query", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "1.1.1.1")
		req.Header.Set("X-Original-Host", "my-app.local")
		req.Header.Set("X-Original-URI", "/profile/edit?user=12")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Wait slightly to make sure the async event processor has written the event to the DB
		time.Sleep(100 * time.Millisecond)

		// Call /api/v1/events
		eventsURL := fmt.Sprintf("%s/api/v1/events?limit=10", serverAddr)
		respEvents, err := http.Get(eventsURL)
		require.NoError(t, err)
		defer respEvents.Body.Close()
		assert.Equal(t, http.StatusOK, respEvents.StatusCode)

		var events []map[string]interface{}
		err = json.NewDecoder(respEvents.Body).Decode(&events)
		require.NoError(t, err)

		// Find the event for 1.1.1.1
		var found bool
		for _, e := range events {
			if e["ip"] == "1.1.1.1" && e["target_host"] == "my-app.local" && e["target_path"] == "/profile/edit?user=12" {
				found = true
				assert.Equal(t, "allow", e["action"])
				break
			}
		}
		assert.True(t, found, "Expected event log with matching metadata not found: %+v", events)
	})

	// Scenario B: Request with safe IP 1.1.1.1 -> expects 200 OK
	t.Run("Safe IP check", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "1.1.1.1")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Scenario C: Request with threat IP 2.2.2.2 -> expects 403 Forbidden
	t.Run("Threat IP check", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "2.2.2.2")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Scenario D: Active Defence Honeytoken Trigger
	// Requesting a honeytoken path (.env) should block the IP (3.3.3.3) and categorize it as threat
	t.Run("Active Defence Honeytoken Trigger", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "3.3.3.3")
		req.Header.Set("X-Original-URI", "/.env")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		// Verification: subsequent normal requests from 3.3.3.3 should be blocked immediately (403)
		req2, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req2.Header.Set("X-Client-IP", "3.3.3.3")
		req2.Header.Set("X-Original-URI", "/index.html")

		resp2, err := http.DefaultClient.Do(req2)
		require.NoError(t, err)
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	})

	// Scenario E: Verify Status Endpoint JSON
	t.Run("Status Endpoint check", func(t *testing.T) {
		resp, err := http.Get(statusURL)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var status map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&status)
		require.NoError(t, err)

		assert.Equal(t, true, status["fail_open"])
		assert.Equal(t, float64(7), status["live_stream_retention_days"])
	})

	// Scenario C.1 & C.2: L1 Cache entries verification
	t.Run("L1 Cache Status check", func(t *testing.T) {
		resp, err := http.Get(statusURL)
		require.NoError(t, err)
		var statusBefore map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&statusBefore)
		resp.Body.Close()
		require.NoError(t, err)

		// Check new IP to populate cache
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "1.1.1.9")
		resp2, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp2.Body.Close()

		resp3, err := http.Get(statusURL)
		require.NoError(t, err)
		var statusAfter map[string]interface{}
		err = json.NewDecoder(resp3.Body).Decode(&statusAfter)
		resp3.Body.Close()
		require.NoError(t, err)

		entriesBefore := statusBefore["l1_cache_entries"].(float64)
		entriesAfter := statusAfter["l1_cache_entries"].(float64)
		assert.Greater(t, entriesAfter, entriesBefore, "L1 cache entries should have increased")
	})

	// Scenario D.2: Manual Threat Reporting via API
	t.Run("Manual Threat Reporting", func(t *testing.T) {
		reportURL := fmt.Sprintf("%s/report-threat", serverAddr)
		req, err := http.NewRequest("POST", reportURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "4.4.4.4")
		req.Header.Set("X-Original-URI", "/manual-report-path")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var res map[string]string
		err = json.NewDecoder(resp.Body).Decode(&res)
		require.NoError(t, err)
		assert.Equal(t, "success", res["status"])

		// Verification: subsequent normal requests from 4.4.4.4 should be blocked immediately (403)
		req2, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req2.Header.Set("X-Client-IP", "4.4.4.4")

		resp2, err := http.DefaultClient.Do(req2)
		require.NoError(t, err)
		defer resp2.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	})

	// Scenario F.1: Serving static assets (GUI root)
	t.Run("Serving static assets", func(t *testing.T) {
		resp, err := http.Get(serverAddr + "/")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "<html")
	})

	// Scenario G.1: Prometheus metrics
	t.Run("Prometheus Metrics Endpoint", func(t *testing.T) {
		resp, err := http.Get(serverAddr + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "repgate_request_count")
	})

	// Scenario H.3: SQL Injection on X-Client-IP header
	t.Run("SQL Injection on X-Client-IP header", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "1.1.1.1' OR 1=1; --")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Rejected by format validator
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	// Scenario H.4: SQL Injection on Metadata headers
	t.Run("SQL Injection on Metadata headers", func(t *testing.T) {
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "1.1.1.1")
		req.Header.Set("X-Original-Host", "'; DROP TABLE ip_records; --")
		req.Header.Set("X-Original-URI", "/index.html'; DELETE FROM events; --")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify that table is not deleted by querying events
		eventsURL := fmt.Sprintf("%s/api/v1/events?limit=5", serverAddr)
		respEvents, err := http.Get(eventsURL)
		require.NoError(t, err)
		defer respEvents.Body.Close()
		assert.Equal(t, http.StatusOK, respEvents.StatusCode)
	})

	// Scenario H.8: SQL Injection on GUI API /api/v1/events query parameters
	t.Run("SQL Injection on GUI API events query parameters", func(t *testing.T) {
		url := fmt.Sprintf("%s/api/v1/events?limit=5;%%20DROP%%20TABLE%%20events;%%20--&before_id=10%%20OR%%201=1&action=allow'%%20OR%%20'1'='1", serverAddr)
		resp, err := http.Get(url)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Safe parsing forces fallback defaults or handles params safely
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Scenario H.9: SQL Injection on report threat
	t.Run("SQL Injection on report threat", func(t *testing.T) {
		reportURL := fmt.Sprintf("%s/report-threat", serverAddr)
		req, err := http.NewRequest("POST", reportURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "127.0.0.1'; DROP TABLE events; --")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Blocked because IP address parsing fails
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	// 7. Stop the server using SIGTERM and verify graceful shutdown
	err = cmd.Process.Signal(syscall.SIGTERM)
	require.NoError(t, err)

	// Wait for the server to exit
	exitErr := cmd.Wait()
	assert.NoError(t, exitErr, "Server did not shut down cleanly")
}

func TestIntegration_FailuresAndResiliency(t *testing.T) {
	binaryPath := getBinaryPath(t)
	tempDir := t.TempDir()

	// 1. Test Case H.1: Malformed Config File
	t.Run("Malformed Configuration File", func(t *testing.T) {
		badConfig := filepath.Join(tempDir, "bad_config.yaml")
		err := os.WriteFile(badConfig, []byte("log_level: : info\nserver:\nport: \"8080\""), 0644)
		require.NoError(t, err)

		cmd := exec.Command(binaryPath, "-c", badConfig)
		cmd.Dir = tempDir

		output, err := cmd.CombinedOutput()
		assert.Error(t, err, "Expected command to fail")
		assert.Contains(t, string(output), "Failed to load configuration")
		if exitError, ok := err.(*exec.ExitError); ok {
			assert.Equal(t, 1, exitError.ExitCode())
		}
	})

	// 2. Test Case H.2: Port Binding Conflict
	t.Run("Port Binding Conflict", func(t *testing.T) {
		// Open a listener on a random port
		port := getFreePort(t)
		addr := fmt.Sprintf("localhost:%d", port)
		l, err := net.Listen("tcp", addr)
		require.NoError(t, err)
		defer l.Close()

		// Write config using that port
		copyMigrations(t, "../../db/migrations", filepath.Join(tempDir, "db", "migrations"))
		err = os.MkdirAll(filepath.Join(tempDir, "data"), 0755)
		require.NoError(t, err)

		configContent := fmt.Sprintf(`
log_level: debug
server:
  port: ":%d"
`, port)
		configFile := filepath.Join(tempDir, "conflict_config.yaml")
		err = os.WriteFile(configFile, []byte(configContent), 0644)
		require.NoError(t, err)

		cmd := exec.Command(binaryPath, "-c", configFile)
		cmd.Dir = tempDir

		output, err := cmd.CombinedOutput()
		assert.Error(t, err, "Expected command to fail due to port conflict")
		assert.Contains(t, string(output), "address already in use")
		if exitError, ok := err.(*exec.ExitError); ok {
			assert.Equal(t, 1, exitError.ExitCode())
		}
	})

	// 3. Test Case H.6 & B.3 / B.4: AbuseIPDB API Unreachable / Offline with fail_open: true
	t.Run("AbuseIPDB API Unreachable with fail_open true", func(t *testing.T) {
		port := getFreePort(t)
		configContent := fmt.Sprintf(`
log_level: debug
fail_open: true
server:
  port: ":%d"
AbuseIPDB:
  enabled: true
  api_key: "test"
  api_url: "http://invalid-domain-name-xyz.com"
  circuit_breaker:
    max_retries: 1
    cool_down_period: 2s
    open_on_error: true
`, port)
		configFile := filepath.Join(tempDir, "unreachable_config.yaml")
		err := os.WriteFile(configFile, []byte(configContent), 0644)
		require.NoError(t, err)

		cmd := exec.Command(binaryPath, "-c", configFile)
		cmd.Dir = tempDir
		err = cmd.Start()
		require.NoError(t, err)
		defer func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}()

		// Wait for server
		serverAddr := fmt.Sprintf("http://localhost:%d", port)
		statusURL := fmt.Sprintf("%s/api/v1/status", serverAddr)
		checkURL := fmt.Sprintf("%s/check", serverAddr)

		var isUp bool
		for i := 0; i < 30; i++ {
			resp, err := http.Get(statusURL)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					isUp = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		require.True(t, isUp, "Server failed to start")

		// Query new IP -> Expect 200 OK because of fail_open: true
		req, err := http.NewRequest("GET", checkURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Client-IP", "8.8.8.8")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
