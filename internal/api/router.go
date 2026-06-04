package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/skoczo/repgate/internal/activedefence"
	"github.com/skoczo/repgate/internal/alerts"
	"github.com/skoczo/repgate/internal/metrics"
	"github.com/skoczo/repgate/internal/model"
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

type Handler struct {
	threatSources  []threatcheck.ThreatSource
	adService      *activedefence.Service
	failOpen       bool
	logSafeIPs     bool
	metrics        *metrics.Metrics
	startTime      time.Time
	mu             sync.Mutex
	lastCacheFetch time.Time
	cachedL2Count  int
	cachedL2Threat int

	eventRepo     *storage.EventRepository
	eventChan     chan model.Event
	subscribers   map[chan model.Event]struct{}
	subMu         sync.Mutex
	retentionDays int
}

func NewRouter(threatSources []threatcheck.ThreatSource, adService *activedefence.Service, failOpen bool, logSafeIPs bool, timeout time.Duration, eventRepo *storage.EventRepository, retentionDays int) http.Handler {
	h := &Handler{
		threatSources: threatSources,
		adService:     adService,
		failOpen:      failOpen,
		logSafeIPs:    logSafeIPs,
		metrics:       metrics.GetMetrics(),
		startTime:     time.Now(),
		eventRepo:     eventRepo,
		eventChan:     make(chan model.Event, 10000),
		subscribers:   make(map[chan model.Event]struct{}),
		retentionDays: retentionDays,
	}
	
	go h.startEventProcessor()

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	for _, source := range h.threatSources {
		source.SetMetrics(h.metrics)
	}

	// Routes with timeout middleware
	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(timeout))

		r.Get("/check", h.checkHandler)
		r.Handle("/metrics", promhttp.Handler())
		r.Get("/api/v1/status", h.statusHandler)
		r.Get("/api/v1/events", h.eventsHandler)
		r.HandleFunc("/report-threat", h.reportThreatHandler)

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
	r.Get("/api/v1/stream/logs", h.streamLogsHandler)

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
	targetPath := r.Header.Get("X-Original-URI")
	if targetPath == "" {
		targetPath = r.URL.Path
	}

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

	// check if the requested path is a honeytoken (if active defence is enabled)
	if h.adService != nil {
		if h.adService.IsHoneytoken(targetPath) {
			if err := h.adService.ReportThreat(r.Context(), ip, targetPath); err != nil {
				slog.Error("failed to report honeytoken threat", "ip", ip, "path", targetPath, "error", err)
			}
			slog.Warn("Threat IP detected via honeytoken path", "ip", ip, "target_host", targetHost, "target_path", targetPath, "alert_id", alerts.ThreatDetected.ID, "alert_name", alerts.ThreatDetected.Name)
			h.metrics.ThreatCount.WithLabelValues(targetHost).Inc()
			h.queueEvent(ip, targetHost, targetPath, "block", "ActiveDefence")
			h.sendResponse(w, StatusForbidden, "IP is a threat")
			return
		}
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
				h.queueEvent(ip, targetHost, targetPath, "allow", source.Name()+" (FailOpen)")
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
			slog.Warn("Threat IP detected", "ip", ip, "target_host", targetHost, "target_path", targetPath, "alert_id", alerts.ThreatDetected.ID, "alert_name", alerts.ThreatDetected.Name)
			h.metrics.ThreatCount.WithLabelValues(targetHost).Inc()
			h.queueEvent(ip, targetHost, targetPath, "block", result.Source)
			h.sendResponse(w, StatusForbidden, "IP is a threat")
			return
		}
	}

	elapsed := time.Since(start_time)
	slog.Debug("request processed", "elapsed", elapsed.String())

	if h.logSafeIPs {
		slog.Info("Safe IP detected", "ip", ip, "target_host", targetHost, "target_path", targetPath)
	}

	h.queueEvent(ip, targetHost, targetPath, "allow", "System")
	h.sendResponse(w, StatusOK, "IP is not a threat")

}

func (h *Handler) sendResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

func (h *Handler) statusHandler(w http.ResponseWriter, r *http.Request) {
	uptimeDuration := time.Since(h.startTime).Round(time.Second)

	var l1Entries, l1Capacity int
	var l2Entries, l2Threats int

	for _, source := range h.threatSources {
		if client, ok := source.(*threatcheck.AbuseIPDBThreatSource); ok {
			l1Entries = client.IPCache.NumOfEntries()
			l1Capacity = client.IPCache.Size()

			h.mu.Lock()
			if time.Since(h.lastCacheFetch) > 15*time.Second {
				if count, err := client.Repo.Count(r.Context()); err == nil {
					h.cachedL2Count = count
				} else {
					slog.Error("failed to get L2 database count for GUI status", "error", err)
				}

				if threats, err := client.Repo.ThreatCount(r.Context()); err == nil {
					h.cachedL2Threat = threats
				} else {
					slog.Error("failed to get L2 database threat count for GUI status", "error", err)
				}
				h.lastCacheFetch = time.Now()
			}
			l2Entries = h.cachedL2Count
			l2Threats = h.cachedL2Threat
			h.mu.Unlock()
			break
		}
	}

	status := model.SystemStatus{
		Uptime:                  uptimeDuration.String(),
		FailOpen:                h.failOpen,
		L1CacheEntries:          l1Entries,
		L1CacheCapacity:         l1Capacity,
		L2CacheEntries:          l2Entries,
		L2ThreatEntries:         l2Threats,
		LiveStreamDisabled:      h.retentionDays == 0,
		LiveStreamRetentionDays: h.retentionDays,
	}

	h.sendResponse(w, StatusOK, status)
}

func (h *Handler) reportThreatHandler(w http.ResponseWriter, r *http.Request) {
	if h.adService == nil {
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

	if err := h.adService.ReportThreat(r.Context(), ip, targetPath); err != nil {
		slog.Error("failed to report threat", "ip", ip, "error", err)
		h.sendResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to report threat"})
		return
	}

	h.sendResponse(w, http.StatusOK, map[string]string{"status": "success", "message": "IP reported as threat"})
}

func (h *Handler) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if h.retentionDays == 0 {
		h.sendResponse(w, http.StatusForbidden, map[string]string{"error": "Livestream functionality is disabled"})
		return
	}

	limitStr := r.URL.Query().Get("limit")
	beforeIDStr := r.URL.Query().Get("before_id")

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

	if h.eventRepo == nil {
		h.sendResponse(w, http.StatusOK, []model.Event{})
		return
	}

	events, err := h.eventRepo.GetEvents(r.Context(), beforeID, limit)
	if err != nil {
		slog.Error("failed to fetch events from repository", "error", err)
		h.sendResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch events"})
		return
	}

	h.sendResponse(w, http.StatusOK, events)
}

func (h *Handler) streamLogsHandler(w http.ResponseWriter, r *http.Request) {
	if h.retentionDays == 0 {
		http.Error(w, "Livestream functionality is disabled", http.StatusForbidden)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := h.subscribe()
	defer h.unsubscribe(ch)

	_, _ = fmt.Fprintf(w, ": ok\n\n")
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func (h *Handler) subscribe() chan model.Event {
	h.subMu.Lock()
	defer h.subMu.Unlock()
	ch := make(chan model.Event, 100)
	h.subscribers[ch] = struct{}{}
	return ch
}

func (h *Handler) unsubscribe(ch chan model.Event) {
	h.subMu.Lock()
	defer h.subMu.Unlock()
	delete(h.subscribers, ch)
	close(ch)
}

func (h *Handler) startEventProcessor() {
	for e := range h.eventChan {
		if h.eventRepo != nil {
			dbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := h.eventRepo.Insert(dbCtx, &e)
			cancel()
			if err != nil {
				slog.Error("failed to save event to database", "error", err)
			}
		}

		h.subMu.Lock()
		for ch := range h.subscribers {
			select {
			case ch <- e:
			default:
			}
		}
		h.subMu.Unlock()
	}
}

func (h *Handler) queueEvent(ip, targetHost, targetPath, action, source string) {
	if h.retentionDays == 0 {
		return
	}

	if source == "" {
		source = "System"
	}
	event := model.Event{
		IP:         ip,
		TargetHost: targetHost,
		TargetPath: targetPath,
		Action:     action,
		Source:     source,
		Timestamp:  time.Now(),
	}
	select {
	case h.eventChan <- event:
	default:
		slog.Warn("event channel full, event dropped", "ip", ip, "action", action)
	}
}
