package activedefence

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
)

// Database defines the storage operations needed by active defence
type Database interface {
	Update(ctx context.Context, record *model.IPRecord) (*model.IPRecord, error)
	GetRecord(ctx context.Context, ip string) (*model.IPRecord, error)
}

// Cache defines the caching operations needed by active defence
type Cache interface {
	Set(ip string, record model.IPRecord)
}

// Service manages active defence features
type Service struct {
	db             Database
	caches         []Cache
	expirationTime time.Duration
	isPermanent    bool
	honeytoken     []*regexp.Regexp
}

// NewService instantiates a new active defence service
func NewService(db Database, caches []Cache, expTimeStr string, honeytokenPaths []string) (*Service, error) {
	expTime, isPermanent, err := parseExpirationTime(expTimeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse active defence expiration time: %w", err)
	}

	var regexes []*regexp.Regexp
	for _, p := range honeytokenPaths {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to compile honeytoken pattern %q: %w", p, err)
		}
		regexes = append(regexes, re)
	}

	return &Service{
		db:             db,
		caches:         caches,
		expirationTime: expTime,
		isPermanent:    isPermanent,
		honeytoken:     regexes,
	}, nil
}

// IsHoneytoken checks if the given request path matches any honeytoken pattern
func (s *Service) IsHoneytoken(path string) bool {
	// Strip query parameters
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	for _, re := range s.honeytoken {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// ReportThreat marks the source IP as a threat in the database and cache
func (s *Service) ReportThreat(ctx context.Context, ip string, path string) error {
	if _, err := netip.ParseAddr(ip); err != nil {
		return fmt.Errorf("invalid IP address: %w", err)
	}

	var expiresAt time.Time
	if s.isPermanent {
		// Use year 9999 to represent permanent / no expiration
		expiresAt = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	} else {
		expiresAt = time.Now().Add(s.expirationTime)
	}

	record := model.IPRecord{
		IP:        ip,
		Status:    "threat",
		Score:     100, // Max threat confidence score
		Source:    "ActiveDefence",
		CheckedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	existingRecord, err := s.db.GetRecord(ctx, ip)
	if err != nil && err != sql.ErrNoRows {
		slog.Error("error checking existing database record", "ip", ip, "error", err)
	}

	_, err = s.db.Update(ctx, &record)
	if err != nil {
		return fmt.Errorf("failed to update threat in database: %w", err)
	}

	for _, cache := range s.caches {
		cache.Set(ip, record)
	}

	// Update metrics
	if existingRecord == nil {
		metrics.GetMetrics().AbuseIpDbDatabaseEntitiesCount.Inc()
		metrics.GetMetrics().AbuseIpDbDatabaseThreatsCount.Inc()
	} else {
		if existingRecord.Status != "threat" {
			metrics.GetMetrics().AbuseIpDbDatabaseThreatsCount.Inc()
		}
	}

	slog.Warn("Honeytoken tripped! Source IP added to threat database and cache", "ip", ip, "path", path)
	return nil
}

// parseExpirationTime converts configuration string to duration/permanent flag
func parseExpirationTime(val string) (time.Duration, bool, error) {
	if val == "permanent" {
		return 0, true, nil
	}
	// Try parsing as standard duration (e.g. "24h")
	d, err := time.ParseDuration(val)
	if err == nil {
		return d, false, nil
	}
	// Try parsing as integer number of hours
	var hours int
	if _, err := fmt.Sscanf(val, "%d", &hours); err == nil && hours > 0 {
		return time.Duration(hours) * time.Hour, false, nil
	}
	return 0, false, fmt.Errorf("invalid expiration time format: %q", val)
}
