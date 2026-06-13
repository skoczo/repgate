package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/event"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/threatcheck"
)

type IPRepository interface {
	ListRecords(ctx context.Context, limit, offset int, search, status, sortBy, sortOrder string) ([]model.IPRecord, int, error)
	Count(ctx context.Context) (int, error)
	ThreatCount(ctx context.Context) (int, error)
}

type Handler struct {
	ThreatSources  []threatcheck.ThreatSource
	AdService      *activedefence.Service
	FailOpen       bool
	LogSafeIPs     bool
	Metrics        *metrics.Metrics
	StartTime      time.Time
	Mu             sync.Mutex
	LastCacheFetch time.Time
	CachedL2Count  int
	CachedL2Threat int

	EventService *event.Service
	IPRepo       IPRepository
}

func NewHandler(threatSources []threatcheck.ThreatSource, adService *activedefence.Service, failOpen bool, logSafeIPs bool, eventService *event.Service, ipRepo IPRepository) *Handler {
	return &Handler{
		ThreatSources:  threatSources,
		AdService:      adService,
		FailOpen:       failOpen,
		LogSafeIPs:     logSafeIPs,
		Metrics:        metrics.GetMetrics(),
		StartTime:      time.Now(),
		EventService:   eventService,
		IPRepo:         ipRepo,
	}
}

func (h *Handler) sendResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

func (h *Handler) PublishEvent(ip, targetHost, targetPath, action, source string) {
	if h.EventService != nil {
		h.EventService.Publish(ip, targetHost, targetPath, action, source)
	}
}
