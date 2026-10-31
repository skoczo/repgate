# 🤖 AGENTS.md — Repgate Agent & Vibe Coding Guide

> **Welcome Agent!** This document contains everything you need to understand, navigate, develop, test, and "vibe code" effectively in the **Repgate** repository. Follow these patterns, rules, and workflows to ensure high quality and zero regressions.

---

## 1. 🛡️ Project Overview & Architecture

**Repgate (Reputation Gate)** is a lightweight, high-performance Go microservice acting as a reverse-proxy gatekeeper (primarily designed for **Nginx** via `auth_request` and **Cloudflare**).

It evaluates client IP reputations against **AbuseIPDB**, enforces **Active Defence (honeytoken paths)**, caches verdicts in a tiered L1/L2 cache, logs structured alerts, exposes Prometheus metrics, and serves an embedded real-time Svelte dashboard.

### High-Level Request Lifecycle (`/check`)

```text
Incoming Request
      │
      ▼
Nginx (auth_request) ──[ Headers: X-Client-IP, X-Original-URI, X-Original-Host ]──► Repgate:8080/check
                                                                                          │
┌─────────────────────────────────────────────────────────────────────────────────────────┴───────────────────────┐
│ 1. Header Validation:                                                                                           │
│    - X-Client-IP missing or invalid? ──► HTTP 403 Forbidden (Alert: CLIENT_IP_HEADER_MISSING / INVALID)         │
│                                                                                                                 │
│ 2. Active Defence (Honeytoken inspection):                                                                      │
│    - Does X-Original-URI match any honeytoken regex (.env, .git, etc.)?                                         │
│      ├── YES: Auto-ban IP for duration (e.g. 48h / permanent), save to L1+L2, optional AbuseIPDB report         │
│      │        ──► HTTP 403 Forbidden                                                                            │
│      └── NO: Proceed to threat sources                                                                          │
│                                                                                                                 │
│ 3. Threat Sources (e.g. AbuseIPDB with Tiered Cache & Circuit Breaker):                                         │
│    - Check L1 Memory Cache (LRU) ──► Hit & valid? Return cached verdict                                         │
│    - Check L2 SQLite Database   ──► Hit & valid? Promote to L1, return verdict                                  │
│    - Cache Miss? Query AbuseIPDB REST API:                                                                      │
│        - Circuit Breaker: If closed, call API. If open/error: check fail_open policy                            │
│        - Store result in L2 SQLite & L1 Memory Cache                                                            │
│                                                                                                                 │
│ 4. Verdict Enforcement:                                                                                         │
│    - Threat score > threshold? ──► Publish Block Event ──► HTTP 403 Forbidden                                   │
│    - Safe?                     ──► Publish Allow Event ──► HTTP 200 OK                                          │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 🗂️ Codebase Map & Responsibilities

```text
repgate/
├── cmd/
│   └── repgate/              # Application entrypoint (main.go), signal handling, cleanup worker, migrations
├── internal/
│   ├── abuseipdb/            # REST client for AbuseIPDB API (CheckIP, ReportThreat)
│   ├── activedefence/        # Active Defence service: honeytoken regex matching, auto-ban, auto-report
│   ├── alerts/               # Standardized structured alert definitions (1xxx Security, 2xxx Validation, 3xxx System)
│   ├── api/                  # HTTP Router (Chi router, middlewares, static asset file server)
│   │   └── handlers/         # API HTTP handlers: /check, /api/v1/status, /api/v1/events, /api/v1/stream/logs
│   ├── cache/                # L1 In-Memory LRU Cache (thread-safe sync.RWMutex, eviction, threat counters)
│   ├── config/               # Configuration loading & validation (YAML parsing, defaults)
│   ├── event/                # Pub/Sub event bus: async buffering channel, SQLite persistence, SSE live broadcast
│   ├── metrics/              # Prometheus metrics (Counters, Gauges, Histograms)
│   ├── model/                # Core domain models (IPRecord, Event, SystemStatus)
│   ├── storage/              # Pure Go SQLite storage (OpenSQLiteDB with WAL mode, IPRepository, Migrations)
│   └── threatcheck/          # ThreatSource interface, CheckContext, AbuseIPDBThreatSource implementation
├── db/
│   └── migrations/           # Plain SQL migration files (001_init.sql, 002_events.sql, 003_reported.sql, ...)
├── web/                      # Embedded Svelte 5 Web GUI Dashboard
│   ├── assets.go             # //go:embed all:dist (Embeds compiled frontend into binary)
│   ├── src/                  # Svelte 5 components (DashboardTab, DatabaseTab, LiveTrafficFeed)
│   └── package.json          # Vite + Svelte 5 + TypeScript build scripts
├── tests/
│   └── integration/          # Integration tests (gated by `//go:build integration`)
├── config.yaml               # Reference configuration
├── internal-config.yaml      # Local/development config (gitignored)
├── Dockerfile                # Multi-stage build (Node -> Go Alpine -> Minimal runtime)
└── Makefile                  # Central task runner
```

---

## 3. ⚙️ Technology Stack & Dependencies

| Layer | Technology | Key Details & Constraints |
| :--- | :--- | :--- |
| **Language** | **Go 1.25+** | Idiomatic Go, `log/slog` structured logging, `net/netip`. |
| **HTTP Framework** | **go-chi/chi/v5** | Lightweight, composable middleware (`RealIP`, `Recoverer`, `Timeout`). |
| **Database** | **modernc.org/sqlite** | **Pure Go SQLite driver** (NO CGO required: builds with `CGO_ENABLED=0`). Uses WAL journal mode & connection pooling. |
| **Frontend** | **Svelte 5 + Vite + TS** | Embeds compiled static assets into the Go binary via `//go:embed all:dist`. |
| **Observability** | **Prometheus** | Metrics on `/metrics`, custom gauges/counters in `internal/metrics`. |
| **Logging** | **log/slog (JSON)** | Standardized alert schema with integer Alert IDs (`internal/alerts`). |

---

## 4. 🚀 Quickstart & Development Workflows

All key workflows are driven by `Makefile`:

```bash
# 1. Build everything (compiles frontend first if web/dist missing, then builds bin/repgate)
make build

# 2. Run unit tests (Fast, offline, 100% mock-based)
make test

# 3. Run unit tests with HTML coverage report
make coverage

# 4. Build the Svelte Web GUI only
make frontend

# 5. Run Repgate locally using internal-config.yaml
make run

# 6. Run performance benchmarks for L1 Cache & get CPU/Memory profiles
make bench-report

# 7. Run integration tests (Requires network and valid ABUSEIPDB_TOKEN environment variable)
make test-integration

# 8. Clean temporary binaries and profiles
make clean
```

---

## 5. ⚠️ Critical Gotchas for Agents ("Vibe Coding Traps")

1. **The `web/dist` Embedding Trap:**
   - In [`web/assets.go`](file:///workspaces/repgate/web/assets.go), Go uses `//go:embed all:dist`.
   - If `web/dist` does not exist, running `go build ./cmd/repgate` or `go run` directly will **fail to compile** with `pattern all:dist: no matching files found`.
   - **Solution:** Always run `make frontend` or `make build`, which automatically checks and builds the frontend before compiling Go code.

2. **CGO Is Disabled (`CGO_ENABLED=0`):**
   - The project uses `modernc.org/sqlite`, a pure Go SQLite implementation.
   - **Do NOT** import `github.com/mattn/go-sqlite3` or any other CGO-dependent package.
   - The Go binary must compile cleanly with `CGO_ENABLED=0`.

3. **Active Defence & Honeytokens Precautions:**
   - Honeytokens in `active_defence.honeytoken_paths` automatically ban client IPs and can report them to AbuseIPDB.
   - When editing regexes, ensure they are strictly anchored or targeted (e.g. `\.env`, `\.git/`) and **never** match standard static assets (`/assets/...`, `/favicon.ico`) or valid API routes.

4. **Required Headers for `/check`:**
   - Client IP must be supplied in `X-Client-IP`. If omitted, `/check` returns `403 Forbidden` (`alerts.ClientIPHeaderMissing`).
   - Host is derived in order: `X-Real-Target` ➔ `X-Forwarded-Host` ➔ `X-Original-Host` ➔ `r.Host`.
   - Path is derived in order: `X-Original-URI` ➔ `r.URL.Path`.

5. **Deterministic Time in Tests:**
   - In `internal/cache/ip_cache.go` and `internal/activedefence/activedefence.go`, components expose `Now func() time.Time`.
   - In unit tests, inject a mock `Now` function (e.g., `cache.Now = func() time.Time { return fixedTime }`) instead of using `time.Sleep`.

6. **Database Schema Changes:**
   - Schema updates must **only** be added as sequential `.sql` files in [`db/migrations/`](file:///workspaces/repgate/db/migrations/) (e.g., `004_new_feature.sql`).
   - `storage.RunMigrations()` tracks applied versions in the `schema_migrations` table automatically.

7. **Protected `main` Branch (Never Commit Directly to `main`):**
   - The `main` branch is protected and direct pushes are rejected.
   - **Always create a dedicated feature or fix branch** (e.g., `feature/...` or `fix/...`) for all changes.
   - Never commit directly to `main`; submit all work via Pull Requests.

---

## 6. 🧩 Extending Repgate: Vibe Coding Recipes

### Recipe A: Adding a New Threat Source (e.g., CrowdSec, GeoIP, Local Blocklist)
1. **Implement the interface** [`threatcheck.ThreatSource`](file:///workspaces/repgate/internal/threatcheck/threatsource.go):
   ```go
   type ThreatSource interface {
       Name() string
       Enabled() bool
       Check(ctx context.Context, req CheckContext) (ThreatCheckResult, error)
       CleanExpired(now time.Time)
       SetMetrics(m *metrics.Metrics)
   }
   ```
2. **Add configuration** fields in [`internal/config/config.go`](file:///workspaces/repgate/internal/config/config.go) and update `config.yaml`.
3. **Wire it up** in `cmd/repgate/main.go` inside `buildThreatSources(...)`.
4. **Write unit tests** in `internal/threatcheck/<your_source>_test.go` using table-driven tests.

### Recipe B: Adding a New API Endpoint
1. **Create the handler method** in [`internal/api/handlers/`](file:///workspaces/repgate/internal/api/handlers/).
2. **Register the route** in [`internal/api/router.go`](file:///workspaces/repgate/internal/api/router.go) under the appropriate timeout/middleware group.
3. **Add route tests** in [`internal/api/router_test.go`](file:///workspaces/repgate/internal/api/router_test.go) asserting response status codes and headers.

### Recipe C: Modifying the Svelte Web Dashboard
1. Edit or add components in [`web/src/lib/`](file:///workspaces/repgate/web/src/lib/).
2. Verify TypeScript and Svelte typing: `npm run check --prefix web`.
3. Build the frontend: `make frontend`.
4. Run the server to preview: `make run`.

---

## 7. 📏 Coding Standards & Conventions

- **Logging**: Use `log/slog` structured attributes. Pair security and operational issues with alerts from `internal/alerts`:
  ```go
  slog.Warn("Threat detected", "ip", ip, "alert_id", alerts.ThreatDetected.ID, "alert_name", alerts.ThreatDetected.Name)
  ```
- **Error Handling**: Wrap errors with context using `fmt.Errorf("...: %w", err)`. Never discard errors silently.
- **Concurrency**: Guard shared state with `sync.RWMutex` or `sync.Mutex`. Use `singleflight.Group` to deduplicate identical concurrent external requests.
- **Fail-Open Policy**: Always respect `cfg.FailOpen`. If an upstream threat provider is unreachable and `FailOpen == true`, allow the request (`200 OK`) and log the degraded state.
- **SSE & Live Events**: Use `eventService.Publish(ip, targetHost, targetPath, action, source)` for any traffic event. Publishing is non-blocking (drops if buffer is saturated).

---

## 8. ✅ Definition of Done (Agent Checklist)

Before submitting or completing a task, verify:
- [ ] Changes are committed to a dedicated feature/fix branch (NEVER directly to `main`).
- [ ] `make test` runs and passes completely.
- [ ] If frontend files were modified, `npm run check --prefix web` passes and `make frontend` builds cleanly.
- [ ] `go mod tidy` does not produce unexpected diffs.
- [ ] No secrets, live API keys, or machine-specific paths were committed.
- [ ] Existing comments and docstrings are preserved.
