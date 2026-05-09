package threatcheck

import (
	"database/sql"
	"log/slog"
	"time"

	"github.com/skoczo/repgate/internal/abuseipdb"
	"github.com/skoczo/repgate/internal/cache"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/storage"
)

type AbuseIPDBClient struct {
	APIKey  string
	Repo    *storage.IPRepository
	Client  *abuseipdb.AbuseIPDBRestClient
	Config  *config.Config
	IPCache *cache.IPCache
}

// initialize ipcache with max size from config
func NewAbuseIPDBClient(cfg *config.Config, repo *storage.IPRepository) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		APIKey:  cfg.AbuseIPDB.APIKey,
		Repo:    repo,
		Client:  abuseipdb.NewAbuseIPDBRestClient(cfg.AbuseIPDB.APIKey),
		Config:  cfg,
		IPCache: cache.NewIPCache(cfg.AbuseIPDB.CacheMaxSize),
	}
}

func (c *AbuseIPDBClient) Name() string {
	return "AbuseIPDB"
}

func (c *AbuseIPDBClient) Enabled() bool {
	return c.APIKey != ""
}

func (c *AbuseIPDBClient) CheckIP(ip string) (ThreatCheckResult, error) {
	// check ip in cache first
	cached_result, exists := c.IPCache.Get(ip)
	if exists {
		slog.Debug("ip found in cache", "ip", ip, "status", cached_result.Status, "score", cached_result.Score)
		if cached_result.ExpiresAt.Before(time.Now()) {
			c.IPCache.Remove(ip)
			c.Repo.Delete(ip)
			slog.Debug("cached result expired, removed from cache and database", "ip", ip)
		} else {
			return ThreatCheckResult{
				IP:       cached_result.IP,
				IsThreat: c.isThread(cached_result.Score),
			}, nil
		}
	}

	result, err := c.Repo.GetByIp(ip)
	if err != nil && err != sql.ErrNoRows {
		slog.Error("error reading ip from cache", "ip", ip, "error", err)
		return ThreatCheckResult{}, err
	}

	if result != nil {
		slog.Debug("ip found in database", "ip", ip, "status", result.Status, "score", result.Score)
		if result.ExpiresAt.Before(time.Now()) {
			// remove expired record from cache and database
			c.IPCache.Remove(ip)
			err = c.Repo.Delete(ip)
		} else {
			c.IPCache.Set(ip, *result)
			return ThreatCheckResult{
				IP:       result.IP,
				IsThreat: c.isThread(result.Score),
			}, nil
		}
	}

	// if not in cache, check abuseipdb and update cache and database
	slog.Debug("ip not found in cache, checking abuseipdb", "ip", ip)
	ip_record, err := c.abuseiddbRequest(ip)
	if err != nil {
		return ThreatCheckResult{}, err
	}

	c.IPCache.Set(ip, *ip_record)
	c.Repo.Update(ip_record)

	return ThreatCheckResult{
		IP:       ip_record.IP,
		IsThreat: c.isThread(ip_record.Score),
	}, nil
}

func (c *AbuseIPDBClient) abuseiddbRequest(ip string) (*model.IPRecord, error) {
	confidenceScore, err := c.Client.CheckIP(ip)
	if err != nil {
		slog.Error("error checking ip in abuseipdb", "ip", ip, "error", err)
		return nil, err
	}

	status := "safe"
	if confidenceScore >= c.Config.AbuseIPDB.ConfidenceScoreThreshold {
		status = "threat"
	}

	ipRecord := model.IPRecord{
		IP:        ip,
		Status:    status,
		Score:     confidenceScore,
		Source:    c.Name(),
		CheckedAt: time.Now(),
		ExpiresAt: time.Now().Add(c.Config.AbuseIPDB.ExpirationTime),
	}

	savedRecord, err := c.Repo.Update(&ipRecord)
	if err != nil {
		slog.Error("error saving ip record to database", "ip", ip, "error", err)
		return nil, err
	}

	return savedRecord, nil
}

func (c *AbuseIPDBClient) isThread(score int) bool {
	if score >= c.Config.AbuseIPDB.ConfidenceScoreThreshold {
		return true
	}
	return false
}
