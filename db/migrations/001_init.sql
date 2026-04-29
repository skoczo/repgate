CREATE TABLE IF NOT EXISTS ip_records (
    ip TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    checked_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_records_expires_at
ON ip_records(expires_at);

CREATE INDEX IF NOT EXISTS idx_ip_records_status
ON ip_records(status);