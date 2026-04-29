package model

import "time"

type IPRecord struct {
	IP        string
	Status    string
	Score     int
	Source    string
	CheckedAt time.Time
	ExpiresAt time.Time
}
