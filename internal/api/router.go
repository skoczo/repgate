package api

import (
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/api/handlers"
	"github.com/skoczo/repgate/internal/event"
	"github.com/skoczo/repgate/internal/storage"
	"github.com/skoczo/repgate/internal/threatcheck"
	"github.com/skoczo/repgate/web"
)

// contract status codes for the API
const (
	StatusOK                  = http.StatusOK
	StatusForbidden           = http.StatusForbidden
	StatusInternalServerError = http.StatusInternalServerError
)

// NewRouter configures routes, sets up middlewares, and registers handlers.
func NewRouter(threatSources []threatcheck.ThreatSource, adService *activedefence.Service, failOpen bool, logSafeIPs bool, timeout time.Duration, eventService *event.Service, ipRepo *storage.IPRepository) http.Handler {
	h := handlers.NewHandler(threatSources, adService, failOpen, logSafeIPs, eventService, ipRepo)

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	for _, source := range h.ThreatSources {
		source.SetMetrics(h.Metrics)
	}

	// Routes with timeout middleware
	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(timeout))

		r.Get("/check", h.CheckHandler)
		r.Handle("/metrics", promhttp.Handler())
		r.Get("/api/v1/status", h.StatusHandler)
		r.Get("/api/v1/events", h.EventsHandler)
		r.Get("/api/v1/db/records", h.DBRecordsHandler)
		r.HandleFunc("/report-threat", h.ReportThreatHandler)

		distFS, err := fs.Sub(web.Assets, "dist")
		if err != nil {
			slog.Error("failed to get sub-filesystem for web assets", "error", err)
		} else {
			fileServer := http.FileServer(http.FS(distFS))
			r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				path := req.URL.Path
				if path == "/" {
					fileServer.ServeHTTP(w, req)
					return
				}
				filePath := path[1:]
				if _, err := distFS.Open(filePath); err != nil {
					if strings.HasPrefix(path, "/api/") {
						http.NotFound(w, req)
						return
					}
					req.URL.Path = "/"
				}
				fileServer.ServeHTTP(w, req)
			}))
		}
	})

	// Routes without timeout middleware
	r.Get("/api/v1/stream/logs", h.StreamLogsHandler)

	return r
}
