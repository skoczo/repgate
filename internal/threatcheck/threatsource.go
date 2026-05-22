package threatcheck

import (
	"time"

	"github.com/skoczo/repgate/internal/metrics"
)

type ThreatSource interface {
	Name() string
	Enabled() bool
	CheckIP(ip string) (ThreatCheckResult, error)
	CleanExpired(now time.Time)
	SetMetrics(m *metrics.Metrics)
}

type ThreatCheckResult struct {
	IP       string
	IsThreat bool
}
