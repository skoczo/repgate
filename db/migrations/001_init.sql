CREATE TABLE IF NOT EXISTS ip_cache (
    ip TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    checked_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_cache_expires_at
ON ip_cache(expires_at);

CREATE INDEX IF NOT EXISTS idx_ip_cache_status
ON ip_cache(status);