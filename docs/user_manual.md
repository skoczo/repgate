# 🛡️ Repgate & Nginx Integration Guide

This guide provides end-to-end instructions for configuring **Repgate** (Reputation Gate) and integrating it with **Nginx** using the `auth_request` module. 

In this setup, Repgate acts as a gatekeeper: Nginx intercepting incoming traffic, querying Repgate to check the client IP's reputation, and either blocking or allowing the request before it reaches your backend services.

---

## 🏗️ Architecture Overview

When a client requests a resource on a proxied domain (e.g., `example.com` or `app.example.com`):

```
Client ──► Nginx (Proxy) ───────────────────────────► Backend Services
             │ ▲ (Intercepts request)                   ▲
             │ │                                        │
    (Auth)   │ │ (200 OK or 403 Forbidden)              │ (If Allowed)
             ▼ │                                        │
          Repgate (Port 8080) ──────────────────────────┘
             │ (Checks L1/L2 Caches)
             ▼
       [ AbuseIPDB API ] (On Cache Miss)
```

For Repgate to log the **correct host** and **original request URI** (instead of defaulting to the internal `repgate:8080` and `/check` path in logs), Nginx must pass specific headers during the authentication sub-request:

* **`X-Original-Host`**: Contains the hostname originally requested by the client (e.g., `example.com`), which maps to `$http_host` in Nginx.
* **`X-Original-URI`**: Contains the full original request path and query parameters (e.g., `/api/v1/users`), which maps to `$request_uri` in Nginx.

### Example configuration snippet:
```nginx
location = /_auth {
    internal;
    proxy_pass http://repgate:8080/check;
    
    # Forward the original request details to Repgate
    proxy_set_header X-Original-Host $http_host;
    proxy_set_header X-Original-URI $request_uri;
}
```

---

## 🌐 Client IP Resolution: Does it only work with Cloudflare Tunnel?

**No. Repgate does not require Cloudflare Tunnel.** It works with any network topology as long as Nginx (or your reverse proxy) passes the client's real IP address to Repgate in the `X-Client-IP` header.

Here is how Nginx handles IP resolution in different environments:

### 1. Behind Cloudflare (Tunnel or CDN)
When using Cloudflare, Cloudflare forwards the client's actual IP address in the `CF-Connecting-IP` header. In Nginx, this is available as `$http_cf_connecting_ip`. 
Nginx uses the following logic to retrieve it:
```nginx
set $client_ip $http_cf_connecting_ip;
```

### 2. Direct Internet Connection (No Cloudflare)
If your Nginx server is exposed directly to the public internet, the client's actual IP is the IP Nginx directly connects to. This is stored in `$remote_addr`.
In this case, the Nginx fallback logic automatically kicks in:
```nginx
if ($client_ip = "") {
    set $client_ip $remote_addr;
}
```
This sets `$client_ip` to the connection IP.

### 3. Behind another Load Balancer/Proxy (e.g., AWS ALB, Traefik)
If you are behind a different proxy, they usually pass the client IP in standard headers like `X-Forwarded-For` or `X-Real-IP`. You can configure Nginx's `ngx_http_realip_module` to restore the correct client IP to `$remote_addr` so that the fallback logic functions automatically.

---

## 📋 Step 1: Configure Repgate

### 1. Configuration File Setup
Repgate reads configuration from a YAML file. Copy the default `config.yaml` to `internal-config.yaml` (which is git-ignored by default):

```bash
cp config.yaml internal-config.yaml
```

### 2. Configure Configuration Properties
Open `internal-config.yaml` and configure the settings. Below is a production-ready template:

```yaml
# Logging settings
log_level: info
log_safe_ips: true          # Set to true to log allowed requests in the live feed
live_stream_retention_days: 7

# Resiliency
fail_open: true             # If AbuseIPDB API is down, allow traffic anyway (fail-safe)

server:
  port: ":8080"
  read_timeout: 5s
  write_timeout: 10s
  read_header_timeout: 2s

AbuseIPDB:
  enabled: true
  api_key: "your_abuseipdb_api_key_here"  # Replace with your actual AbuseIPDB API key
  expiration_time: 24h                    # How long to cache checked IPs locally
  confidence_score_threshold: 50          # IPs with AbuseIPDB confidence score > 50 are blocked
  cache_max_size: 1000                    # Maximum in-memory (L1) cache size
  circuit_breaker:
    max_retries: 3
    cool_down_period: 30s
    open_on_error: true

active_defence:
  enabled: true
  expiration_time: "permanent"            # Auto-block attackers hitting honeytokens permanently
  honeytoken_paths:                       # Common paths scanned by bots/attackers
    - '\.env'
    - '\.git/'
    - 'wp-login\.php'
    - 'phpinfo'
```

### 3. Start Repgate
Depending on your deployment method, run Repgate using one of the following options:

* **Docker Compose (Recommended):**
  Ensure Repgate runs in the same Docker network as your Nginx container.
  ```bash
  docker-compose -f docker/docker-compose.yml up -d
  ```

* **Standalone Binary Build:**
  ```bash
  make build
  ./bin/repgate --config internal-config.yaml
  ```

---

## ⚙️ Step 2: Configure Nginx

To protect your domains and ensure Repgate receives correct metadata, Nginx needs to be configured with the `ngx_http_auth_request_module` (usually compiled into Nginx by default).

Below is an example configuration protecting two separate domains:
1. `example.com` (Standard Web App)
2. `stream.example.com` (Service requiring WebSocket support, e.g., camera streams or dashboards)

### Complete `nginx.conf` Template

```nginx
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    
    # Enable access logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;

    # ==========================================
    # SERVER 1: STANDARD WEB APP (example.com)
    # ==========================================
    server {
        listen 80;
        server_name example.com;

        # Serve a custom block page if Repgate returns 403 Forbidden
        error_page 403 = /blocked.html;

        location / {
            # Enable Repgate protection for this location
            auth_request /_auth;
            
            # Proxy to the application backend
            proxy_pass http://webapp_backend:8000;
            
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Internal authentication endpoint queried by Nginx
        location = /_auth {
            internal;
            
            # Points to the Repgate container or service
            proxy_pass http://repgate:8080/check;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            
            # CRITICAL: Forward the original domain and path requested by the client
            proxy_set_header X-Original-Host $http_host;
            proxy_set_header X-Original-URI $request_uri;
            
            # Extract real client IP (Use $http_cf_connecting_ip if behind Cloudflare)
            set $client_ip $http_cf_connecting_ip;
            if ($client_ip = "") {
                set $client_ip $remote_addr;
            }
            proxy_set_header X-Client-IP $client_ip;
        }

        # Custom block page definition
        location = /blocked.html {
            internal;
            default_type text/html;
            return 200 "<html><body><h1>Request Blocked</h1><p>Your IP has been identified as a security risk and blocked by our system.</p></body></html>";
        }
    }

    # ==========================================
    # SERVER 2: WEBSOCKET SERVICE (stream.example.com)
    # ==========================================
    server {
        listen 80;
        server_name stream.example.com;

        error_page 403 = /blocked.html;

        location / {
            auth_request /_auth;
            
            # Proxy to the streaming backend
            proxy_pass http://stream_backend:8971;
            
            # Disable SSL verification if proxying to self-signed backend SSL/TLS
            proxy_ssl_verify off; 
            
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket support (CRITICAL for live feeds and connections)
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        # Internal authentication endpoint queried by Nginx
        location = /_auth {
            internal;
            proxy_pass http://repgate:8080/check;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            
            # CRITICAL: Forward the original domain and path requested by the client
            proxy_set_header X-Original-Host $http_host;
            proxy_set_header X-Original-URI $request_uri;
            
            # Extract real client IP (Use $http_cf_connecting_ip if behind Cloudflare)
            set $client_ip $http_cf_connecting_ip;
            if ($client_ip = "") {
                set $client_ip $remote_addr;
            }
            proxy_set_header X-Client-IP $client_ip;
        }

        location = /blocked.html {
            internal;
            default_type text/html;
            return 200 "<html><body><h1>Request Blocked</h1><p>Your IP has been identified as a security risk and blocked by our system.</p></body></html>";
        }
    }
}
```

---

## 🔍 Step 3: Verification & Log Inspection

Once Nginx and Repgate are restarted, incoming requests will begin appearing in the Repgate live feed.

### Correct Behavior (Headers Properly Configured)
If the headers are forwarded correctly, the Repgate logs/live feed will display the actual domain and requested path:

```text
12:15:30
198.51.100.42
ALLOW
System
example.com
/api/v1/users

12:15:32
203.0.113.88
ALLOW
System
stream.example.com
/live/feed?camera=1
```

### Incorrect Behavior (Headers Missing)
If `X-Original-Host` and `X-Original-URI` are **not** present in the Nginx `/_auth` block, the logs will show the internal backend URL instead:

```text
12:15:30
198.51.100.42
ALLOW
System
repgate:8080
/check
```

If you notice this incorrect format, verify that your Nginx configuration contains the following lines inside the `location = /_auth` blocks:
```nginx
proxy_set_header X-Original-Host $http_host;
proxy_set_header X-Original-URI $request_uri;
```

---

## 🛠️ Troubleshooting

### 1. "X-Client-IP header is not set" Alert
If you see the alert `CLIENT_IP_HEADER_MISSING` (`2001`) in Repgate logs, it means Nginx is not passing the IP correctly to Repgate.
* Make sure `proxy_set_header X-Client-IP $client_ip;` is defined in the `location = /_auth` block.
* If testing locally without a proxy, ensure the header fallback evaluates to a valid client IP.

### 2. Client gets 500 Internal Server Error
If Nginx returns a `500 Internal Server Error` to the client, it usually means Nginx is unable to connect to the Repgate service (e.g., Repgate is down/offline).

* Check if the Repgate service is running and accessible: `curl http://localhost:8080/api/v1/status`.
* Verify Nginx error logs at `/var/log/nginx/error.log` for resolver or upstream connection refused/timeout errors.
* **Understanding fail-open settings:**
  * **Repgate's `fail_open`:** The `fail_open: true` setting in Repgate's `internal-config.yaml` only applies when Repgate *is* running, but its downstream threat sources (like the AbuseIPDB API) are offline or failing.
  * **Nginx's `fail_open` (if Repgate is down):** By default, Nginx will block traffic with a `500` status if Repgate is offline. To configure Nginx to fail open (allow requests through) if Repgate cannot be reached, you can intercept upstream errors in Nginx and return a `200` status:

    ```nginx
    location = /_auth {
        internal;
        proxy_pass http://repgate:8080/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        
        proxy_set_header X-Original-Host $http_host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Client-IP $client_ip;

        # Fail open if Repgate is offline/unreachable
        proxy_intercept_errors on;
        error_page 500 502 503 504 =200 /_auth_fail_open;
    }

    location = /_auth_fail_open {
        internal;
        return 200; # Allow traffic to pass through
    }
    ```
