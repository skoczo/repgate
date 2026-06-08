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
		if client, ok := source.(*threatcheck.AbuseIPDBThreatSource); ok {
			l1Entries = client.IPCache.NumOfEntries()
			l1Capacity = client.IPCache.Size()

			h.Mu.Lock()
			if time.Since(h.LastCacheFetch) > 15*time.Second {
				if count, err := client.Repo.Count(r.Context()); err == nil {
					h.CachedL2Count = count
				} else {
					slog.Error("failed to get L2 database count for GUI status", "error", err)
				}

				if threats, err := client.Repo.ThreatCount(r.Context()); err == nil {
					h.CachedL2Threat = threats
				} else {
					slog.Error("failed to get L2 database threat count for GUI status", "error", err)
				}
				h.LastCacheFetch = time.Now()
			}
			l2Entries = h.CachedL2Count
			l2Threats = h.CachedL2Threat
			h.Mu.Unlock()
			break
		}
	}

	status := model.SystemStatus{
		Uptime:                  uptimeDuration.String(),
		FailOpen:                h.FailOpen,
		L1CacheEntries:          l1Entries,
		L1CacheCapacity:         l1Capacity,
		L2CacheEntries:          l2Entries,
		L2ThreatEntries:         l2Threats,
		LiveStreamDisabled:      h.RetentionDays == 0,
		LiveStreamRetentionDays: h.RetentionDays,
	}

	h.sendResponse(w, http.StatusOK, status)
}
