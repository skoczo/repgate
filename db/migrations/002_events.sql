CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    target_host TEXT NOT NULL,
    target_path TEXT NOT NULL,
    action TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON events(timestamp);
