package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AbuseIPDBRestClient struct {
	APIKey string
}

func (c *AbuseIPDBRestClient) CheckIP(ip string) (int, error) {
	/*
				example abusedb response
				{"data":{"ipAddress":"165.154.23.177","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"HK","usageType":"Data Center\/Web Hosting\/Transit","isp":"UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED","domain":"ucloud.cn","hostnames":[],"isTor":false,"totalReports":2067,"numDistinctUsers":165,"lastReportedAt":"2026-04-30T20:02:20+00:00"}}
		time=2026-04-30T20:08:39.042Z level=ERROR msg="Error checking IP %s in AbuseIPDBClient: %v" 165.154
	*/
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	// set timeout to 10 seconds
	var client = &http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("abuseipdb returned status code %d", resp.StatusCode)
	}
	defer resp.Body.Close()

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
	fmt.Println("AbuseIPDB response:", string(body))

	if err := json.Unmarshal(body, &result); err != nil {
		return 0, err
	}

	return result.Data.AbuseConfidenceScore, nil
}
