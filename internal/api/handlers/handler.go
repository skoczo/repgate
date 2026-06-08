package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
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

	EventRepo     *storage.EventRepository
	EventChan     chan model.Event
	Subscribers   map[chan model.Event]struct{}
	SubMu         sync.Mutex
	RetentionDays int
	IPRepo        *storage.IPRepository
}

func NewHandler(threatSources []threatcheck.ThreatSource, adService *activedefence.Service, failOpen bool, logSafeIPs bool, eventRepo *storage.EventRepository, retentionDays int, ipRepo *storage.IPRepository) *Handler {
	h := &Handler{
		ThreatSources:  threatSources,
		AdService:      adService,
		FailOpen:       failOpen,
		LogSafeIPs:     logSafeIPs,
		Metrics:        metrics.GetMetrics(),
		StartTime:      time.Now(),
		EventRepo:      eventRepo,
		EventChan:      make(chan model.Event, 10000),
		Subscribers:    make(map[chan model.Event]struct{}),
		RetentionDays:  retentionDays,
		IPRepo:         ipRepo,
	}

	go h.startEventProcessor()

	return h
}

func (h *Handler) sendResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

func (h *Handler) subscribe() chan model.Event {
	h.SubMu.Lock()
	defer h.SubMu.Unlock()
	ch := make(chan model.Event, 100)
	h.Subscribers[ch] = struct{}{}
	return ch
}

func (h *Handler) unsubscribe(ch chan model.Event) {
	h.SubMu.Lock()
	defer h.SubMu.Unlock()
	delete(h.Subscribers, ch)
	close(ch)
}

func (h *Handler) startEventProcessor() {
	for e := range h.EventChan {
		if h.EventRepo != nil {
			dbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := h.EventRepo.Insert(dbCtx, &e)
			cancel()
			if err != nil {
				slog.Error("failed to save event to database", "error", err)
			}
		}

		h.SubMu.Lock()
		for ch := range h.Subscribers {
			select {
			case ch <- e:
			default:
			}
		}
		h.SubMu.Unlock()
	}
}

func (h *Handler) QueueEvent(ip, targetHost, targetPath, action, source string) {
	if h.RetentionDays == 0 {
		return
	}

	if source == "" {
		source = "System"
	}
	event := model.Event{
		IP:         ip,
		TargetHost: targetHost,
		TargetPath: targetPath,
		Action:     action,
		Source:     source,
		Timestamp:  time.Now(),
	}
	select {
	case h.EventChan <- event:
	default:
		slog.Warn("event channel full, event dropped", "ip", ip, "action", action)
	}
}
