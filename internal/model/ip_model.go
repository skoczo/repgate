package model

import "time"

type IPRecord struct {
	IP        string
	Status    string
	Score     int
	Source    string
	CreatedAt time.Time
	UpdatedAt time.Time
}
