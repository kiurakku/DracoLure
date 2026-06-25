CREATE TABLE IF NOT EXISTS attacks (
    id SERIAL PRIMARY KEY,
    attack_type VARCHAR(255) NOT NULL,
    source_ip VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45),
    user_agent TEXT,
    request_path TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);
