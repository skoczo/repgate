package threatcheck

import (
	"context"
	"time"

	"github.com/skoczo/repgate/internal/metrics"
)

type ThreatSource interface {
	Name() string
	Enabled() bool
	CheckIP(ctx context.Context, ip string) (ThreatCheckResult, error)
	CleanExpired(now time.Time)
	SetMetrics(m *metrics.Metrics)
}

type ThreatCheckResult struct {
	IP       string
	IsThreat bool
}
