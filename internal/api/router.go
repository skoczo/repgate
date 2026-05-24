package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skoczo/repgate/internal/alerts"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/threatcheck"
)

// contract status codes for the API
const (
	StatusOK                  = http.StatusOK
	StatusForbidden           = http.StatusForbidden
	StatusInternalServerError = http.StatusInternalServerError
)

type Handler struct {
	threatSources []threatcheck.ThreatSource
	failOpen      bool
	metrics       *metrics.Metrics
}

func NewRouter(threatSources []threatcheck.ThreatSource, failOpen bool, timeout time.Duration) http.Handler {
	h := &Handler{
		threatSources: threatSources,
		failOpen:      failOpen,
		metrics:       metrics.GetMetrics(),
	}
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(timeout))

	for _, source := range h.threatSources {
		source.SetMetrics(h.metrics)
	}

	r.Get("/check", h.checkHandler)
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func getTargetHost(r *http.Request) string {
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

func (h *Handler) checkHandler(w http.ResponseWriter, r *http.Request) {
	// log time taken to process the request in Us
	start_time := time.Now()
	targetHost := getTargetHost(r)

	defer func() {
		elapsed := time.Since(start_time)
		slog.Debug("request completed", "elapsed", elapsed.String())
		h.metrics.RequestDuration.WithLabelValues(targetHost).Observe(float64(elapsed.Seconds()))
		h.metrics.RequestCount.WithLabelValues(targetHost).Inc()
	}()

	// log full message with all the headers
	slog.Debug("request received", "headers", r.Header)

	// validate if x-client-ip is set and is a valid ip address
	ip := r.Header.Get("X-Client-IP")
	if ip == "" {
		slog.Warn("X-Client-IP header is not set", "alert_id", alerts.ClientIPHeaderMissing.ID, "alert_name", alerts.ClientIPHeaderMissing.Name)
		h.sendResponse(w, StatusForbidden, "X-Client-IP header is not set")
		return
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		slog.Warn("X-Client-IP header is not a valid IP address", "ip", ip, "alert_id", alerts.ClientIPHeaderInvalid.ID, "alert_name", alerts.ClientIPHeaderInvalid.Name)
		h.sendResponse(w, StatusForbidden, "X-Client-IP header is not a valid IP address")
		return
	}

	for _, source := range h.threatSources {
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
			if h.failOpen {
				h.sendResponse(w, StatusOK, "Source is not available")
				return
			}
			h.sendResponse(w, StatusInternalServerError, err.Error())
			return
		}
		if slog.Default().Enabled(r.Context(), slog.LevelDebug) {
			slog.Debug("threat check result", "source", source.Name(), "is_threat", result.IsThreat)
		}
		if result.IsThreat {
			targetPath := r.Header.Get("X-Original-URI")
			if targetPath == "" {
				targetPath = r.URL.Path
			}
			slog.Warn("Threat IP detected", "ip", ip, "target_host", targetHost, "target_path", targetPath, "alert_id", alerts.ThreatDetected.ID, "alert_name", alerts.ThreatDetected.Name)
			h.metrics.ThreatCount.WithLabelValues(targetHost).Inc()
			h.sendResponse(w, StatusForbidden, "IP is a threat")
			return
		}
	}

	elapsed := time.Since(start_time)
	slog.Debug("request processed", "elapsed", elapsed.String())

	h.sendResponse(w, StatusOK, "IP is not a threat")

}

func (h *Handler) sendResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}
