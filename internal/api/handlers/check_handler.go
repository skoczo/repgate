package handlers

import (
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/skoczo/repgate/internal/alerts"
)

func GetTargetHost(r *http.Request) string {
	if target := r.Header.Get("X-Real-Target"); target != "" {
		return target
	}
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	if host := r.Header.Get("X-Original-Host"); host != "" {
		return host
	}
	return r.Host
}

func (h *Handler) CheckHandler(w http.ResponseWriter, r *http.Request) {
	// log time taken to process the request in Us
	start_time := time.Now()
	targetHost := GetTargetHost(r)
	targetPath := r.Header.Get("X-Original-URI")
	if targetPath == "" {
		targetPath = r.URL.Path
	}

	defer func() {
		elapsed := time.Since(start_time)
		slog.Debug("request completed", "elapsed", elapsed.String())
		h.Metrics.RequestDuration.WithLabelValues(targetHost).Observe(float64(elapsed.Seconds()))
		h.Metrics.RequestCount.WithLabelValues(targetHost).Inc()
	}()

	// log full message with all the headers
	slog.Debug("request received", "headers", r.Header)

	// validate if x-client-ip is set and is a valid ip address
	ip := r.Header.Get("X-Client-IP")
	if ip == "" {
		slog.Warn("X-Client-IP header is not set", "alert_id", alerts.ClientIPHeaderMissing.ID, "alert_name", alerts.ClientIPHeaderMissing.Name)
		h.sendResponse(w, http.StatusForbidden, "X-Client-IP header is not set")
		return
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		slog.Warn("X-Client-IP header is not a valid IP address", "ip", ip, "alert_id", alerts.ClientIPHeaderInvalid.ID, "alert_name", alerts.ClientIPHeaderInvalid.Name)
		h.sendResponse(w, http.StatusForbidden, "X-Client-IP header is not a valid IP address")
		return
	}

	// check if the requested path is a honeytoken (if active defence is enabled)
	if h.AdService != nil {
		if h.AdService.IsHoneytoken(targetPath) {
			if err := h.AdService.ReportThreat(r.Context(), ip, targetPath); err != nil {
				slog.Error("failed to report honeytoken threat", "ip", ip, "path", targetPath, "error", err)
			}
			slog.Warn("Threat IP detected via honeytoken path", "ip", ip, "target_host", targetHost, "target_path", targetPath, "alert_id", alerts.ThreatDetected.ID, "alert_name", alerts.ThreatDetected.Name)
			h.Metrics.ThreatCount.WithLabelValues(targetHost).Inc()
			h.QueueEvent(ip, targetHost, targetPath, "block", "ActiveDefence")
			h.sendResponse(w, http.StatusForbidden, "IP is a threat")
			return
		}
	}

	for _, source := range h.ThreatSources {
		if !source.Enabled() {
			if slog.Default().Enabled(r.Context(), slog.LevelDebug) {
				slog.Debug("threat source disabled, skipping", "source", source.Name())
			}
			continue
		}
		if slog.Default().Enabled(r.Context(), slog.LevelDebug) {
			slog.Debug("checking threat source", "source", source.Name())
		}
		result, err := source.CheckIP(r.Context(), ip)

		if err != nil {
			slog.Error("error checking threat source", "source", source.Name(), "error", err, "alert_id", alerts.ThreatSourceCheckError.ID, "alert_name", alerts.ThreatSourceCheckError.Name)
			if h.FailOpen {
				h.QueueEvent(ip, targetHost, targetPath, "allow", source.Name()+" (FailOpen)")
				h.sendResponse(w, http.StatusOK, "Source is not available")
				return
			}
			h.sendResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		if slog.Default().Enabled(r.Context(), slog.LevelDebug) {
			slog.Debug("threat check result", "source", source.Name(), "is_threat", result.IsThreat)
		}
		if result.IsThreat {
			slog.Warn("Threat IP detected", "ip", ip, "target_host", targetHost, "target_path", targetPath, "alert_id", alerts.ThreatDetected.ID, "alert_name", alerts.ThreatDetected.Name)
			h.Metrics.ThreatCount.WithLabelValues(targetHost).Inc()
			h.QueueEvent(ip, targetHost, targetPath, "block", result.Source)
			h.sendResponse(w, http.StatusForbidden, "IP is a threat")
			return
		}
	}

	elapsed := time.Since(start_time)
	slog.Debug("request processed", "elapsed", elapsed.String())

	if h.LogSafeIPs {
		slog.Info("Safe IP detected", "ip", ip, "target_host", targetHost, "target_path", targetPath)
	}

	h.QueueEvent(ip, targetHost, targetPath, "allow", "System")
	h.sendResponse(w, http.StatusOK, "IP is not a threat")
}
