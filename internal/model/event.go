package model

import "time"

type Event struct {
	ID         int64     `json:"id"`
	IP         string    `json:"ip"`
	TargetHost string    `json:"target_host"`
	TargetPath string    `json:"target_path"`
	Action     string    `json:"action"` // e.g. "allow", "block", "tarpit"
	Source     string    `json:"source"` // e.g. "AbuseIPDB", "ActiveDefence", "System"
	Timestamp  time.Time `json:"timestamp"`
}
