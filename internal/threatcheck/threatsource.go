package threatcheck

type ThreatSource interface {
	Name() string
	Enabled() bool
	CheckIP(ip string) (ThreatCheckResult, error)
}

type ThreatCheckResult struct {
	IP       string
	IsThreat bool
}
