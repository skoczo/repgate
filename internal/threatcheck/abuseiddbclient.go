package threatcheck

import (
	"log"

	"github.com/skoczo/repgate/internal/storage"
)

type AbuseIPDBClient struct {
	APIKey string
	Repo   storage.IPRepository
}

func (c *AbuseIPDBClient) Name() string {
	return "AbuseIPDB"
}

func (c *AbuseIPDBClient) Enabled() bool {
	return c.APIKey != ""
}

func (c *AbuseIPDBClient) CheckIP(ip string) (ThreatCheckResult, error) {

	result, err := c.Repo.GetByIp(ip)
	if err != nil {
		// Log the error and return a non-threat result
		log.Fatalf("Error checking IP %s in AbuseIPDBClient: %v", ip, err)
		return ThreatCheckResult{
			IP:       ip,
			IsThreat: false,
		}, nil
	}
	if result != nil {
		return ThreatCheckResult{
			IP:       ip,
			IsThreat: result.Score > 0,
		}, nil
	}

	return ThreatCheckResult{
		IP:       ip,
		IsThreat: false, // Set this based on the API response
	}, nil
}
