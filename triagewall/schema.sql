CREATE TABLE IF NOT EXISTS triage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    flow_id INTEGER,                         -- nullable: decoder alerts have no flow
    src_ip TEXT,                             -- nullable
    src_port INTEGER,                        -- nullable
    dest_ip TEXT,                            -- nullable
    dest_port INTEGER,                       -- nullable
    proto TEXT,                              -- nullable
    in_iface TEXT,                           -- you have this consistently
    pkt_src TEXT,                            -- you have this consistently
    
    signature_id INTEGER NOT NULL,           -- always present
    signature TEXT NOT NULL,                 -- always present
    category TEXT,
    severity INTEGER,
    action TEXT,                             -- allowed/blocked
    
    raw_alert TEXT NOT NULL,                 -- full JSON for re-processing
    
    -- Agent verdict
    verdict TEXT,                            -- 'real' | 'false_positive' | 'uncertain' | NULL until processed
    confidence REAL,
    reasoning TEXT,
    model_used TEXT,
    processed_at TEXT,
    
    -- Human feedback
    human_verdict TEXT,
    human_notes TEXT,
    agreed BOOLEAN,
    reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_triage_dup_check ON triage_events(flow_id, signature_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_model_processed_at ON triage_events(model_used, processed_at);

CREATE INDEX IF NOT EXISTS idx_triage_timestamp ON triage_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_triage_signature_id ON triage_events(signature_id);
CREATE INDEX IF NOT EXISTS idx_triage_verdict ON triage_events(verdict);
CREATE INDEX IF NOT EXISTS idx_triage_processed ON triage_events(processed_at);

-- Complete input records that cannot be triaged are retained before the
-- ingest checkpoint advances, so malformed or unsupported input is not lost.
CREATE TABLE IF NOT EXISTS ingest_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_line TEXT NOT NULL,
    error TEXT NOT NULL,
    failed_at TEXT NOT NULL
);
