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

type AbuseIPDBThreatSource struct {
	APIKey  string
	Repo    *storage.IPRepository
	Client  *abuseipdb.AbuseIPDBRestClient
	Config  *config.Config
	IPCache *cache.IPCache
}

// initialize ipcache with max size from config
func NewAbuseIPDBClient(cfg *config.Config, repo *storage.IPRepository) *AbuseIPDBThreatSource {
	return &AbuseIPDBThreatSource{
		APIKey:  cfg.AbuseIPDB.APIKey,
		Repo:    repo,
		Client:  abuseipdb.NewAbuseIPDBRestClient(cfg.AbuseIPDB.APIKey),
		Config:  cfg,
		IPCache: cache.NewIPCache(cfg.AbuseIPDB.CacheMaxSize),
	}
}

func (c *AbuseIPDBThreatSource) Name() string {
	return "AbuseIPDB"
}

func (c *AbuseIPDBThreatSource) Enabled() bool {
	return c.APIKey != ""
}

func (c *AbuseIPDBThreatSource) CheckIP(ip string) (ThreatCheckResult, error) {
	// check ip in cache first
	cached_result, exists := c.IPCache.Get(ip)
	if exists {
		slog.Debug("ip found in cache", "ip", ip, "status", cached_result.Status, "score", cached_result.Score)
		if cached_result.ExpiresAt.Before(time.Now()) {
			cleanExpiredIP(c, ip)
		} else {
			return c.createResult(cached_result.IP, cached_result.Score), nil
		}
	}

	result, err := c.Repo.GetByIp(ip)
	if err != nil && err != sql.ErrNoRows {
		slog.Error("error reading ip from cache", "ip", ip, "error", err)
		return ThreatCheckResult{}, err
	}

	if result != nil {
		slog.Debug("ip found in database", "ip", ip, "status", result.Status, "score", result.Score)
		c.IPCache.Set(ip, *result)
		return c.createResult(result.IP, result.Score), nil
	}

	// if not in cache, check abuseipdb and update cache and database
	slog.Debug("ip not found in cache, checking abuseipdb", "ip", ip)
	ip_record, err := c.abuseiddbRequest(ip)
	if err != nil {
		return ThreatCheckResult{}, err
	}

	c.IPCache.Set(ip, *ip_record)
	c.Repo.Update(ip_record)

	return c.createResult(ip_record.IP, ip_record.Score), nil
}

func cleanExpiredIP(c *AbuseIPDBThreatSource, ip string) {
	c.IPCache.Remove(ip)
	err := c.Repo.Delete(ip)
	if err != nil {
		slog.Error("error deleting ip record from cache", "ip", ip, "error", err)
	}
	slog.Debug("cached result expired, removed from cache and database", "ip", ip)
}

func (c *AbuseIPDBThreatSource) abuseiddbRequest(ip string) (*model.IPRecord, error) {
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

func (c *AbuseIPDBThreatSource) createResult(ip string, score int) ThreatCheckResult {
	return ThreatCheckResult{
		IP:       ip,
		IsThreat: c.isThread(score),
	}
}

func (c *AbuseIPDBThreatSource) isThread(score int) bool {
	if score >= c.Config.AbuseIPDB.ConfidenceScoreThreshold {
		return true
	}
	return false
}
