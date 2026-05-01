package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
}

func NewRouter(threatSources []threatcheck.ThreatSource, failOpen bool) http.Handler {
	h := &Handler{threatSources: threatSources, failOpen: failOpen}
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(5 * time.Second))

	r.Get("/check", h.checkHanlder)

	return r
}

func (h *Handler) checkHanlder(w http.ResponseWriter, r *http.Request) {
	slog.Debug("request received",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("remote_addr", r.RemoteAddr),
		slog.String("x_client_ip", r.Header.Get("X-Client-IP")),
		slog.String("cf_connecting_ip", r.Header.Get("CF-Connecting-IP")),
		slog.String("user_agent", r.UserAgent()),
		slog.String("host", r.Host))

	for _, source := range h.threatSources {
		if !source.Enabled() {
			slog.Debug("threat source disabled, skipping", "source", source.Name())
			continue
		}
		slog.Debug("checking threat source", "source", source.Name())
		result, err := source.CheckIP(r.Header.Get("X-Client-IP"))

		if err != nil {
			slog.Error("error checking threat source", "source", source.Name(), "error", err)
			if h.failOpen {
				h.sentResponse(w, StatusOK, "Source is not available")
				return
			}
			h.sentResponse(w, StatusInternalServerError, err.Error())
			return
		}
		slog.Debug("threat check result", "source", source.Name(), "is_threat", result.IsThreat)
		if result.IsThreat {
			h.sentResponse(w, StatusForbidden, "IP is a threat")
			return
		}
	}

	h.sentResponse(w, StatusOK, "IP is not a threat")
}

func (h *Handler) sentResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}
