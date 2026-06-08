package handlers

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
)

func (h *Handler) ReportThreatHandler(w http.ResponseWriter, r *http.Request) {
	if h.AdService == nil {
		h.sendResponse(w, http.StatusNotFound, map[string]string{"error": "Active defence is disabled"})
		return
	}

	ip := r.Header.Get("X-Client-IP")
	if ip == "" {
		// Fallback to RemoteAddr (excluding port)
		var err error
		if ip, _, err = net.SplitHostPort(r.RemoteAddr); err != nil {
			ip = r.RemoteAddr
		}
	}

	if _, err := netip.ParseAddr(ip); err != nil {
		h.sendResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid client IP address"})
		return
	}

	targetPath := r.Header.Get("X-Original-URI")
	if targetPath == "" {
		targetPath = r.URL.Path
	}

	if err := h.AdService.ReportThreat(r.Context(), ip, targetPath); err != nil {
		slog.Error("failed to report threat", "ip", ip, "error", err)
		h.sendResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to report threat"})
		return
	}

	h.sendResponse(w, http.StatusOK, map[string]string{"status": "success", "message": "IP reported as threat"})
}
