package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(5 * time.Second))

	r.Get("/check", checkHanlder)

	return r
}

func checkHanlder(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	slog.Info("request received",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("remote_addr", r.RemoteAddr),
		slog.String("x_client_ip", r.Header.Get("X-Client-IP")),
		slog.String("cf_connecting_ip", r.Header.Get("CF-Connecting-IP")),
		slog.String("user_agent", r.UserAgent()),
		slog.String("host", r.Host))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"message": "server is running",
		"took_ms": time.Since(start).Milliseconds(),
	})
}
