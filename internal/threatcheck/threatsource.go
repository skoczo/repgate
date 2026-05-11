package threatcheck

import "time"

type ThreatSource interface {
	Name() string
	Enabled() bool
	CheckIP(ip string) (ThreatCheckResult, error)
	CleanExpired(now time.Time)
}

type ThreatCheckResult struct {
	IP       string
	IsThreat bool
}
