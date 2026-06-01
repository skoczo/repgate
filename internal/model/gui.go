package model

type SystemStatus struct {
	Uptime          string `json:"uptime"`
	FailOpen        bool   `json:"fail_open"`
	L1CacheEntries  int    `json:"l1_cache_entries"`
	L1CacheCapacity int    `json:"l1_cache_capacity"`
	L2CacheEntries  int    `json:"l2_cache_entries"`
	L2ThreatEntries int    `json:"l2_threat_entries"`
}
