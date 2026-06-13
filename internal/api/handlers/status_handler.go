package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/skoczo/repgate/internal/model"
	"github.com/skoczo/repgate/internal/threatcheck"
)

func (h *Handler) StatusHandler(w http.ResponseWriter, r *http.Request) {
	uptimeDuration := time.Since(h.StartTime).Round(time.Second)

	var l1Entries, l1Capacity int
	var l2Entries, l2Threats int

	for _, source := range h.ThreatSources {
		if statable, ok := source.(threatcheck.Statable); ok {
			l1Entries, l1Capacity = statable.CacheStats()
			break
		}
	}

	h.Mu.Lock()
	if h.IPRepo != nil && time.Since(h.LastCacheFetch) > 15*time.Second {
		if count, err := h.IPRepo.Count(r.Context()); err == nil {
			h.CachedL2Count = count
		} else {
			slog.Error("failed to get L2 database count for GUI status", "error", err)
		}

		if threats, err := h.IPRepo.ThreatCount(r.Context()); err == nil {
			h.CachedL2Threat = threats
		} else {
			slog.Error("failed to get L2 database threat count for GUI status", "error", err)
		}
		h.LastCacheFetch = time.Now()
	}
	l2Entries = h.CachedL2Count
	l2Threats = h.CachedL2Threat
	h.Mu.Unlock()

	retDays := 0
	if h.EventService != nil {
		retDays = h.EventService.RetentionDays()
	}

	status := model.SystemStatus{
		Uptime:                  uptimeDuration.String(),
		FailOpen:                h.FailOpen,
		L1CacheEntries:          l1Entries,
		L1CacheCapacity:         l1Capacity,
		L2CacheEntries:          l2Entries,
		L2ThreatEntries:         l2Threats,
		LiveStreamDisabled:      retDays == 0,
		LiveStreamRetentionDays: retDays,
	}

	h.sendResponse(w, http.StatusOK, status)
}
