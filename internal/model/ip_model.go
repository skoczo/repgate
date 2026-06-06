package model

import "time"

type IPRecord struct {
	IP        string    `json:"ip"`
	Status    string    `json:"status"`
	Score     int       `json:"score"`
	Source    string    `json:"source"`
	CheckedAt time.Time `json:"checked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
