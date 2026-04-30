package threatcheck

import (
	"log/slog"
	"time"

	"github.com/skoczo/repgate/internal/abuseipdb"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/storage"
)

type AbuseIPDBClient struct {
	APIKey string
	Repo   storage.IPRepository
	Client *abuseipdb.AbuseIPDBRestClient
	Config *config.Config
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
		slog.Error("Error checking IP %s in AbuseIPDBClient: %v", ip, err)
		return ThreatCheckResult{
			IP:       ip,
			IsThreat: false,
		}, nil
	}

	if result != nil {
		if result.ExpiresAt.Before(time.Now()) {
			return c.abuseiddbRequest(ip)
		}

		return ThreatCheckResult{
			IP:       ip,
			IsThreat: result.Score > c.Config.AbuseIPDB.ConfidenceScoreThreshold,
		}, nil
	} else {
		return c.abuseiddbRequest(ip)
	}
}

func (c *AbuseIPDBClient) abuseiddbRequest(ip string) (ThreatCheckResult, error) {
	confidenceScore, err := c.Client.CheckIP(ip)
	if err != nil {
		slog.Error("Error checking IP %s in AbuseIPDBClient: %v", ip, err)
		return ThreatCheckResult{
			IP:       ip,
			IsThreat: false,
		}, nil
	}

	if confidenceScore > c.Config.AbuseIPDB.ConfidenceScoreThreshold {
		c.Repo.Update(&model.IPRecord{
			IP:        ip,
			Status:    "threat",
			Score:     confidenceScore,
			Source:    c.Name(),
			CheckedAt: time.Now(),
			ExpiresAt: time.Now().Add(c.Config.AbuseIPDB.ExpirationTime),
		})

		return ThreatCheckResult{
			IP:       ip,
			IsThreat: true,
		}, nil
	} else {
		c.Repo.Update(&model.IPRecord{
			IP:        ip,
			Status:    "safe",
			Score:     confidenceScore,
			Source:    c.Name(),
			CheckedAt: time.Now(),
			ExpiresAt: time.Now().Add(c.Config.AbuseIPDB.ExpirationTime),
		})
		return ThreatCheckResult{
			IP:       ip,
			IsThreat: false,
		}, nil
	}
}
