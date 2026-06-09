package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
)

func (h *Handler) EventsHandler(w http.ResponseWriter, r *http.Request) {
	if h.EventService == nil || h.EventService.RetentionDays() == 0 {
		h.sendResponse(w, http.StatusForbidden, map[string]string{"error": "Livestream functionality is disabled"})
		return
	}

	limitStr := r.URL.Query().Get("limit")
	beforeIDStr := r.URL.Query().Get("before_id")
	action := r.URL.Query().Get("action")
	if action != "allow" && action != "block" {
		action = ""
	}

	limit := 50
	if limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 {
			limit = val
			if limit > 100 {
				limit = 100
			}
		}
	}

	var beforeID int64
	if beforeIDStr != "" {
		if val, err := strconv.ParseInt(beforeIDStr, 10, 64); err == nil && val > 0 {
			beforeID = val
		}
	}

	events, err := h.EventService.GetEvents(r.Context(), beforeID, limit, action)
	if err != nil {
		slog.Error("failed to fetch events from repository", "error", err)
		h.sendResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch events"})
		return
	}

	h.sendResponse(w, http.StatusOK, events)
}
