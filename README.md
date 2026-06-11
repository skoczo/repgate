[![codecov](https://codecov.io/gh/skoczo/repgate/graph/badge.svg)](https://codecov.io/gh/skoczo/repgate)
[![Repgate CI](https://github.com/skoczo/repgate/actions/workflows/go.yml/badge.svg)](https://github.com/adskoczy/repgate/actions/workflows/go.yml)

# 🛡️ Repgate (Reputation Gate)

<div align="center">
  <img src="assets/logo.png" alt="Repgate Logo" width="150" />
  <p><em>Secure your infrastructure with real-time IP reputation filtering.</em></p>
</div>

---

**Repgate** is a high-performance, lightweight Go service designed to serve as a middleware gatekeeper for your web applications. It fetches, caches, and serves IP reputation data from **AbuseIPDB**, allowing you to block malicious traffic at the edge (e.g., in Nginx) before it even reaches your backend services.

It is specifically optimized for environments behind **Cloudflare** or **Nginx**, where client source IPs are passed in headers.

## ✨ Key Features

- ⚡ **High Performance**: Written in Go with [Chi](https://github.com/go-chi/chi) for minimal overhead.
- 🗄️ **Smart Caching**: SQLite-backed persistent cache to minimize API calls and ensure fast responses.
- 🔌 **Seamless Integration**: Designed to work perfectly with Nginx's `auth_request` module.
- 🛡️ **Resilient Architecture**: Built-in **Circuit Breaker** and configurable **Fail-Open/Fail-Closed** modes.
- 📊 **Observability**: Native **Prometheus** metrics and structured logging.
- 🛡️ **Active Defence**: Define custom honeytoken paths (e.g. `.env`, `.git`) to auto-block attackers, with optional background reporting to AbuseIPDB.
- 🐳 **Docker Ready**: Easy to deploy via Docker and Docker Compose.
- 🛠️ **Dev Friendly**: Full Dev Container support for VS Code.

---

## 🏗️ How it Works

Repgate acts as an authorization endpoint. When a request hits your reverse proxy (Nginx):
1. Nginx sends a sub-request to Repgate's `/check` endpoint.
2. Repgate identifies the client's real IP (handling Cloudflare/Proxy headers).
3. **Tiered Caching Check**:
   - **L1 (In-Memory)**: Checks a fast, thread-safe memory cache for immediate results.
   - **L2 (SQLite)**: If not in L1, checks the local SQLite database for persistent records.
4. **API Query**: If not cached, it queries AbuseIPDB, updates both caches, and enforces the confidence threshold.
5. **Enforcement**: If the IP is malicious, Repgate returns `403 Forbidden`. Otherwise, it returns `200 OK`.

---

## 🚀 Getting Started

### 1. Requirements
- **Go 1.25+** (Required for the latest `modernc.org/sqlite` driver)
- **GNU Make**
- **AbuseIPDB API Key**

### 2. Installation
```bash
git clone https://github.com/skoczo/repgate.git
cd repgate
go mod tidy
```

### 3. Configuration
Create an `internal-config.yaml` file in the root directory (copying from `config.yaml`):

```yaml
log_level: info
fail_open: true # Allow traffic if AbuseIPDB is unreachable

server:
  port: ":8080"
  read_timeout: 5s
  write_timeout: 10s

AbuseIPDB:
  enabled: true
  api_key: "YOUR_API_KEY_HERE"
  expiration_time: 24h
  confidence_score_threshold: 50 # Block if score > 50
  cache_max_size: 1000
  circuit_breaker:
    max_retries: 3
    cool_down_period: 30s
    open_on_error: true

active_defence:
  enabled: true
  expiration_time: "permanent" # Auto-block attackers permanently
  honeytoken_paths:
    - '\.env'
    - '\.git/'
  auto_report: false # Automatically report detected IPs to AbuseIPDB
  report_categories:
    - 21 # Web App Attack
  report_comment: "Honeytoken tripped"
```

### 4. Running
**Using Make:**
```bash
make build
./bin/repgate
```

**Using Docker Compose:**
```bash
docker-compose -f docker/docker-compose.yml up --build
```

---

## 🔗 Nginx Integration

Use the `auth_request` module to protect your services:

```nginx
server {
    listen 80;

    location / {
        auth_request /_auth;
        proxy_pass http://your_backend;
    }

    location = /_auth {
        internal;
        proxy_pass http://repgate:8080/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        
        # Pass real client IP (Cloudflare example)
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    }
}
```

---

## 📊 Monitoring & Metrics

Repgate exposes Prometheus metrics at `:8080/metrics`:

| Metric | Type | Description |
| :--- | :--- | :--- |
| `repgate_request_count` | Counter | Total number of IP checks processed (labeled by host). |
| `repgate_request_duration_seconds` | Histogram | Latency of requests (labeled by host). |
| `repgate_threat_count` | Counter | Total number of malicious IPs detected (labeled by host). |

---

## 🚨 Alerts & Structured Logging

Repgate writes structured logs using Go's `slog` library. When critical security events, client configuration errors, or system anomalies occur, log entries are enriched with `alert_id` (numeric, for dashboarding/querying in Grafana Loki) and `alert_name` (string, for developer readability) fields.

### Alert Classification Schema

- **`1xxx` Series**: Security events (e.g. threat detection, client IP blocks).
- **`2xxx` Series**: Client/Request configuration errors (e.g. missing/invalid headers).
- **`3xxx` Series**: System/Dependency errors (e.g. SQLite database or external AbuseIPDB API failures).

| Alert ID | Alert Name (`alert_name`) | Severity | Description |
| :--- | :--- | :--- | :--- |
| **`1001`** | `THREAT_DETECTED` | `WARN` | A malicious IP attempted to reach the proxied backend host. |
| **`2001`** | `CLIENT_IP_HEADER_MISSING` | `WARN` | Request reached `/check` without the `X-Client-IP` header. |
| **`2002`** | `CLIENT_IP_HEADER_INVALID` | `WARN` | `X-Client-IP` header was not a valid IP address. |
| **`3001`** | `THREAT_SOURCE_CHECK_FAILED` | `ERROR` | Internal database query or threat check failed. |
| **`3002`** | `CIRCUIT_BREAKER_TRIPPED` | `WARN` | Cache miss occurred but AbuseIPDB request was skipped (circuit open). |
| **`3003`** | `DATABASE_WRITE_FAILED` | `ERROR` | Failed to persist check result to SQLite cache database. |
| **`3004`** | `EXTERNAL_CHECK_FAILED` | `ERROR` | Network/API failure during HTTP check request to AbuseIPDB. |

---

## 🛠️ Development

### Database & Migrations
Repgate uses a CGO-free SQLite driver.
- **Database Path**: `data/repgate.db`
- **Migrations**: Found in `db/migrations/`

### Makefile Commands
- `make build`: Compiles the binary.
- `make test`: Runs unit tests.
- `make lint`: Runs golangci-lint.
- `make docker-build`: Builds the Docker image.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.