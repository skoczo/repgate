package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/skoczo/repgate/internal/alerts"
	"golang.org/x/sync/singleflight"
)

type AbuseIPDBRestClient struct {
	APIKey           string
	AbuseIPDBRestUrl string
	HTTPClient       *http.Client
	requestGroup     *singleflight.Group
}

func NewAbuseIPDBRestClient(apiKey string) *AbuseIPDBRestClient {
	return &AbuseIPDBRestClient{
		APIKey:           apiKey,
		AbuseIPDBRestUrl: "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90",
		HTTPClient:       &http.Client{Timeout: 3 * time.Second},
		requestGroup:     &singleflight.Group{},
	}
}

func (c *AbuseIPDBRestClient) CheckIP(ctx context.Context, ip string) (int, error) {
	/*
		example abusedb response
		{"data":{"ipAddress":"165.154.23.177","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"HK","usageType":"Data Center\/Web Hosting\/Transit","isp":"UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED","domain":"ucloud.cn","hostnames":[],"isTor":false,"totalReports":2067,"numDistinctUsers":165,"lastReportedAt":"2026-04-30T20:02:20+00:00"}
		time=2026-04-30T20:08:39.042Z level=ERROR msg="Error checking IP %s in AbuseIPDBClient: %v" 165.154
	*/
	ch := c.requestGroup.DoChan(ip, func() (any, error) {
		u, err := url.Parse(c.AbuseIPDBRestUrl)
		if err != nil {
			return 0, err
		}

		q := u.Query()
		q.Set("ipAddress", ip)
		u.RawQuery = q.Encode()

		// Use a decoupled context with configured HTTP timeout to prevent single request cancels
		// from aborting shared singleflight HTTP executions for other concurrent waiters.
		ctxHTTP, cancel := context.WithTimeout(context.Background(), c.HTTPClient.Timeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctxHTTP, "GET", u.String(), nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Key", c.APIKey)
		req.Header.Set("Accept", "application/json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("abuseipdb returned status code %d", resp.StatusCode)
		}

		var result struct {
			Data struct {
				AbuseConfidenceScore int `json:"abuseConfidenceScore"`
			} `json:"data"`
		}

		// print full body for debugging purposes
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, err
		}
		slog.Debug("AbuseIPDB response:", "response", string(body))

		if err := json.Unmarshal(body, &result); err != nil {
			return 0, err
		}

		return result.Data.AbuseConfidenceScore, nil
	})

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			slog.Error("Error checking IP in AbuseIPDBClient", "error", res.Err, "alert_id", alerts.ExternalCheckFailed.ID, "alert_name", alerts.ExternalCheckFailed.Name)
			return 0, res.Err
		}
		slog.Debug("AbuseIPDB response:", "response", res.Val)
		return res.Val.(int), nil
	}
}
