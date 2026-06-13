package threatcheck

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/skoczo/repgate/internal/abuseipdb"
	"github.com/skoczo/repgate/internal/alerts"
	"github.com/skoczo/repgate/internal/cache"
	"github.com/skoczo/repgate/internal/config"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/storage"
)

type AbuseIPDBThreatSource struct {
	APIKey  string
	Repo    *storage.IPRepository
	Client  abuseipdb.Client
	Config  *config.Config
	IPCache *cache.IPCache

	cbMu         sync.Mutex
	cbFailures   int
	cbLastFailed time.Time
	metrics      *metrics.Metrics
}

// initialize ipcache with max size from config
func NewAbuseIPDBClient(cfg *config.Config, repo *storage.IPRepository, client abuseipdb.Client) *AbuseIPDBThreatSource {
	return &AbuseIPDBThreatSource{
		APIKey:  cfg.AbuseIPDB.APIKey,
		Repo:    repo,
		Client:  client,
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

func (c *AbuseIPDBThreatSource) allowRequest() bool {
	c.cbMu.Lock()
	defer c.cbMu.Unlock()

	if c.cbFailures >= c.Config.AbuseIPDB.CircuitBreaker.MaxRetries {
		if time.Since(c.cbLastFailed) < c.Config.AbuseIPDB.CircuitBreaker.CoolDownPeriod {
			return false // Circuit is open
		}
		// Half-open: allow request, if it fails cbLastFailed will be updated
	}
	return true
}

func (c *AbuseIPDBThreatSource) recordSuccess() {
	c.cbMu.Lock()
	defer c.cbMu.Unlock()
	c.cbFailures = 0
}

func (c *AbuseIPDBThreatSource) recordFailure() {
	c.cbMu.Lock()
	defer c.cbMu.Unlock()
	c.cbFailures++
	c.cbLastFailed = time.Now()
}

func (c *AbuseIPDBThreatSource) Check(ctx context.Context, req CheckContext) (ThreatCheckResult, error) {
	ip := req.IP

	// update metrics in defer
	defer func() {
		if c.metrics == nil {
			return
		}
		c.metrics.AbuseIpDbCacheSize.Set(float64(c.IPCache.Size()))
		c.metrics.AbuseIpDbCacheEntitiesCount.Set(float64(c.IPCache.NumOfEntries()))
		c.metrics.AbuseIpDbCacheThreatsCount.Set(float64(c.IPCache.ThreatCount()))
	}()

	// check ip in cache first
	cached_result, exists := c.IPCache.Get(ip)
	if exists {
		slog.Debug("ip found in cache", "ip", ip, "status", cached_result.Status, "score", cached_result.Score)
		if cached_result.ExpiresAt.Before(time.Now()) {
			cleanExpiredIP(ctx, c, ip)
		} else {
			return c.createResult(cached_result.IP, cached_result.Score, cached_result.Source), nil
		}
	}

	result, err := c.Repo.GetByIp(ctx, ip)
	if err != nil && err != sql.ErrNoRows {
		slog.Error("error reading ip from cache", "ip", ip, "error", err)
		return ThreatCheckResult{}, err
	}

	if result != nil {
		slog.Debug("ip found in database", "ip", ip, "status", result.Status, "score", result.Score)
		c.IPCache.Set(ip, *result)
		return c.createResult(result.IP, result.Score, result.Source), nil
	}

	// if not in cache, check abuseipdb and update cache and database
	if !c.allowRequest() {
		slog.Warn("circuit breaker open, skipping abuseipdb request", "ip", ip, "alert_id", alerts.CircuitBreakerTripped.ID, "alert_name", alerts.CircuitBreakerTripped.Name)
		if c.Config.AbuseIPDB.CircuitBreaker.OpenOnError {
			return c.createResult(ip, 0, ""), nil // Fail open, return safe
		}
		return ThreatCheckResult{}, errors.New("circuit breaker open")
	}

	slog.Debug("ip not found in cache, checking abuseipdb", "ip", ip)
	ip_record, err := c.abuseiddbRequest(ctx, ip)
	if err != nil {
		c.recordFailure()
		if c.Config.AbuseIPDB.CircuitBreaker.OpenOnError {
			return c.createResult(ip, 0, ""), nil // Fail open, return safe
		}
		return ThreatCheckResult{}, err
	}
	c.recordSuccess()

	c.IPCache.Set(ip, *ip_record)

	return c.createResult(ip_record.IP, ip_record.Score, ip_record.Source), nil
}

func cleanExpiredIP(ctx context.Context, c *AbuseIPDBThreatSource, ip string) {
	record, exists := c.IPCache.Get(ip)
	c.IPCache.Remove(ip)
	err := c.Repo.Delete(ctx, ip)
	if err != nil {
		slog.Error("error deleting ip record from database", "ip", ip, "error", err)
	} else {
		if c.metrics != nil {
			c.metrics.AbuseIpDbDatabaseEntitiesCount.Dec()
			if exists && record.Status == "threat" {
				c.metrics.AbuseIpDbDatabaseThreatsCount.Dec()
			}
		}
	}
	slog.Debug("cached result expired, removed from cache and database", "ip", ip)
}

func (c *AbuseIPDBThreatSource) CleanExpired(now time.Time) {
	c.IPCache.RemoveExpired(now)
	if c.metrics != nil {
		c.metrics.AbuseIpDbCacheSize.Set(float64(c.IPCache.Size()))
		c.metrics.AbuseIpDbCacheEntitiesCount.Set(float64(c.IPCache.NumOfEntries()))
		c.metrics.AbuseIpDbCacheThreatsCount.Set(float64(c.IPCache.ThreatCount()))
	}
}

func (c *AbuseIPDBThreatSource) abuseiddbRequest(ctx context.Context, ip string) (*model.IPRecord, error) {
	confidenceScore, err := c.Client.CheckIP(ctx, ip)
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

	// Fetch existing record (even if expired) to decide on metric updates
	existingRecord, err := c.Repo.GetRecord(ctx, ip)
	if err != nil && err != sql.ErrNoRows {
		slog.Error("error reading existing record from database", "ip", ip, "error", err)
	}

	savedRecord, err := c.Repo.Update(ctx, &ipRecord)
	if err != nil {
		slog.Error("error saving ip record to database", "ip", ip, "error", err, "alert_id", alerts.DatabaseWriteFailed.ID, "alert_name", alerts.DatabaseWriteFailed.Name)
		return nil, err
	}

	if c.metrics != nil {
		if existingRecord == nil {
			// Brand new record inserted
			c.metrics.AbuseIpDbDatabaseEntitiesCount.Inc()
			if status == "threat" {
				c.metrics.AbuseIpDbDatabaseThreatsCount.Inc()
			}
		} else {
			// Record updated. Adjust threat count if status transitioned.
			if existingRecord.Status != "threat" && status == "threat" {
				c.metrics.AbuseIpDbDatabaseThreatsCount.Inc()
			} else if existingRecord.Status == "threat" && status != "threat" {
				c.metrics.AbuseIpDbDatabaseThreatsCount.Dec()
			}
		}
	}

	return savedRecord, nil
}

func (c *AbuseIPDBThreatSource) createResult(ip string, score int, source string) ThreatCheckResult {
	return ThreatCheckResult{
		IP:       ip,
		IsThreat: c.isThreat(score),
		Source:   source,
	}
}

func (c *AbuseIPDBThreatSource) isThreat(score int) bool {
	if score >= c.Config.AbuseIPDB.ConfidenceScoreThreshold {
		return true
	}
	return false
}

func (c *AbuseIPDBThreatSource) SetMetrics(m *metrics.Metrics) {
	c.metrics = m
}

func (c *AbuseIPDBThreatSource) CacheStats() (int, int) {
	if c.IPCache != nil {
		return c.IPCache.NumOfEntries(), c.IPCache.Size()
	}
	return 0, 0
}
