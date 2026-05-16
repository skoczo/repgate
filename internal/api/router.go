package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	metrics       *Metrics
}

type Metrics struct {
	RequestCount    *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	ThreatCount     *prometheus.CounterVec
}

func NewRouter(threatSources []threatcheck.ThreatSource, failOpen bool, timeout time.Duration) http.Handler {
	h := &Handler{
		threatSources: threatSources,
		failOpen:      failOpen,
		metrics:       GetMetrics(),
	}
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(timeout))

	r.Get("/check", h.checkHandler)
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func (h *Handler) checkHandler(w http.ResponseWriter, r *http.Request) {
	// log time taken to process the request in Us
	start_time := time.Now()

	defer func() {
		elapsed := time.Since(start_time)
		slog.Debug("request completed", "elapsed", elapsed.String())
		h.metrics.RequestDuration.WithLabelValues(r.Host).Observe(float64(elapsed.Seconds()))
		h.metrics.RequestCount.WithLabelValues(r.Host).Inc()
	}()

	if slog.Default().Enabled(r.Context(), slog.LevelDebug) {
		debugFields := []any{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("x_client_ip", r.Header.Get("X-Client-IP")),
			slog.String("cf_connecting_ip", r.Header.Get("CF-Connecting-IP")),
			slog.String("user_agent", r.UserAgent()),
			slog.String("host", r.Host),
		}
		if originalURI := r.Header.Get("X-Original-URI"); originalURI != "" {
			debugFields = append(debugFields, slog.String("original_uri", originalURI))
		}
		if originalMethod := r.Header.Get("X-Original-Method"); originalMethod != "" {
			debugFields = append(debugFields, slog.String("original_method", originalMethod))
		}
		slog.Debug("request received", debugFields...)
	}

	// validate if x-client-ip is set and is a valid ip address
	ip := r.Header.Get("X-Client-IP")
	if ip == "" {
		slog.Warn("X-Client-IP header is not set")
		h.sendResponse(w, StatusForbidden, "X-Client-IP header is not set")
		return
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		slog.Warn("X-Client-IP header is not a valid IP address", "ip", ip)
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
		result, err := source.CheckIP(ip)

		if err != nil {
			slog.Error("error checking threat source", "source", source.Name(), "error", err)
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
			slog.Warn("Threat IP wanted to reach", "ip", ip, "host", r.Host, "path", targetPath)
			h.metrics.ThreatCount.WithLabelValues(r.Host).Inc()
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

var (
	metricInstance *Metrics
	metricsSync    sync.Once
)

func GetMetrics() *Metrics {
	metricsSync.Do(func() {
		metricInstance = &Metrics{
			RequestCount: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "repgate_request_count",
					Help: "Number of requests",
				},
				[]string{"host"},
			),
			RequestDuration: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "repgate_request_duration_seconds",
					Help:    "Duration of requests",
					Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
				},
				[]string{"host"},
			),
			ThreatCount: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "repgate_threat_count",
					Help: "Number of threats",
				},
				[]string{"host"},
			),
		}
	})
	return metricInstance
}
