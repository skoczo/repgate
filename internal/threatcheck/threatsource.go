package threatcheck

import (
	"context"
	"time"

	"github.com/skoczo/repgate/internal/metrics"
)

type CheckContext struct {
	IP   string
	Path string
	Host string
}

type ThreatSource interface {
	Name() string
	Enabled() bool
	Check(ctx context.Context, req CheckContext) (ThreatCheckResult, error)
	CleanExpired(now time.Time)
	SetMetrics(m *metrics.Metrics)
}

type ThreatCheckResult struct {
	IP       string
	IsThreat bool
	Source   string
}
