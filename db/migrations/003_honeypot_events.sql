CREATE TABLE IF NOT EXISTS honeypot_events (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(64) NOT NULL,
    method VARCHAR(10),
    path TEXT,
    query TEXT,
    user_agent TEXT,
    categories TEXT[],
    threat_score INTEGER NOT NULL DEFAULT 0,
    severity VARCHAR(16),
    payload TEXT,
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON honeypot_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON honeypot_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON honeypot_events (severity);
