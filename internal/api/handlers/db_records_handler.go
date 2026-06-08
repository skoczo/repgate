package handlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/skoczo/repgate/internal/model"
)

func (h *Handler) DBRecordsHandler(w http.ResponseWriter, r *http.Request) {
	if h.IPRepo == nil {
		h.sendResponse(w, http.StatusOK, map[string]any{
			"records": []model.IPRecord{},
			"total":   0,
		})
		return
	}

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	search := r.URL.Query().Get("search")
	status := r.URL.Query().Get("status")
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")

	limit := 50
	if limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 {
			limit = val
			if limit > 500 {
				limit = 500
			}
		}
	}

	offset := 0
	if offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil && val >= 0 {
			offset = val
		}
	}

	if sortBy == "" {
		sortBy = "expires_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	records, total, err := h.IPRepo.ListRecords(r.Context(), limit, offset, search, status, sortBy, sortOrder)
	if err != nil {
		slog.Error("failed to list database IP records", "error", err)
		h.sendResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to query database records"})
		return
	}

	h.sendResponse(w, http.StatusOK, map[string]any{
		"records": records,
		"total":   total,
	})
}
