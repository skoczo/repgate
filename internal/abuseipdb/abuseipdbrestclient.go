package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skoczo/repgate/internal/alerts"
	"golang.org/x/sync/singleflight"
)

type AbuseIPDBRestClient struct {
	APIKey                 string
	AbuseIPDBRestCheckUrl  string
	AbuseIPDBRestReportUrl string
	HTTPClient             *http.Client
	requestGroup           *singleflight.Group
}

var (
	defaultClient *AbuseIPDBRestClient
	once          sync.Once
)

// InitClient initializes the default AbuseIPDBRestClient singleton.
func InitClient(apiKey string) *AbuseIPDBRestClient {
	once.Do(func() {
		defaultClient = NewAbuseIPDBRestClient(apiKey)
	})
	return defaultClient
}

// GetClient returns the default AbuseIPDBRestClient singleton instance.
func GetClient() *AbuseIPDBRestClient {
	return defaultClient
}

// SetClient overrides the default AbuseIPDBRestClient singleton instance (mostly for testing).
func SetClient(client *AbuseIPDBRestClient) {
	defaultClient = client
}

func NewAbuseIPDBRestClient(apiKey string) *AbuseIPDBRestClient {
	return &AbuseIPDBRestClient{
		APIKey:                 apiKey,
		AbuseIPDBRestCheckUrl:  "https://api.abuseipdb.com/api/v2/check",
		AbuseIPDBRestReportUrl: "https://api.abuseipdb.com/api/v2/report",
		HTTPClient:             &http.Client{Timeout: 3 * time.Second},
		requestGroup:           &singleflight.Group{},
	}
}

func (c *AbuseIPDBRestClient) CheckIP(ctx context.Context, ip string) (int, error) {
	/*
		example abusedb response
		{"data":{"ipAddress":"165.154.23.177","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"HK","usageType":"Data Center\/Web Hosting\/Transit","isp":"UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED","domain":"ucloud.cn","hostnames":[],"isTor":false,"totalReports":2067,"numDistinctUsers":165,"lastReportedAt":"2026-04-30T20:02:20+00:00"}
		time=2026-04-30T20:08:39.042Z level=ERROR msg="Error checking IP %s in AbuseIPDBClient: %v" 165.154
	*/
	ch := c.requestGroup.DoChan(ip, func() (any, error) {
		u, err := url.Parse(c.AbuseIPDBRestCheckUrl)
		if err != nil {
			return 0, err
		}

		q := u.Query()
		q.Set("ipAddress", ip)
		q.Set("maxAgeInDays", "90")
		u.RawQuery = q.Encode()

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

/*
 report: Report an IP address to AbuseIPDB using REST API

 example: curl -X POST https://api.abuseipdb.com/api/v2/report \\
   -H "Key: [ENCRYPTION_KEY]" \\
   -H "Accept: application/json" \\
   -d "ip=123.123.123.123" \\
   -d "categories=14,18" \\
   -d "comment=This IP address has been identified as participating in malicious activities."
*/

func (c *AbuseIPDBRestClient) ReportIP(ctx context.Context, ip string, categories []int, comment string) error {
	u, err := url.Parse(c.AbuseIPDBRestReportUrl)
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set("ipAddress", ip)

	categoriesStrings := make([]string, len(categories))
	for i, c := range categories {
		categoriesStrings[i] = strconv.Itoa(c)
	}
	q.Set("categories", strings.Join(categoriesStrings, ","))
	q.Set("comment", comment)
	u.RawQuery = q.Encode()

	ctxHTTP, cancel := context.WithTimeout(context.Background(), c.HTTPClient.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctxHTTP, "POST", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("abuseipdb returned status code %d", resp.StatusCode)
	}

	return nil
}
