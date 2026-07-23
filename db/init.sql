-- Legacy manual attack log (kept for the /attack endpoint & backward compat).
CREATE TABLE IF NOT EXISTS attacks (
    id SERIAL PRIMARY KEY,
    attack_type VARCHAR(255) NOT NULL,
    source_ip VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Raw request log written by the Go service.
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45),
    user_agent TEXT,
    request_path TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Classified intrusion events produced by the detection engine.
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

CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON honeypot_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON honeypot_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON honeypot_events (severity);
