package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/event"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/storage"
	"github.com/skoczo/repgate/internal/threatcheck"
)

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
	IPRepo       *storage.IPRepository
}

func NewHandler(threatSources []threatcheck.ThreatSource, adService *activedefence.Service, failOpen bool, logSafeIPs bool, eventService *event.Service, ipRepo *storage.IPRepository) *Handler {
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
