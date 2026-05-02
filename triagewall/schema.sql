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

CREATE INDEX idx_triage_timestamp ON triage_events(timestamp);
CREATE INDEX idx_triage_signature_id ON triage_events(signature_id);
CREATE INDEX idx_triage_verdict ON triage_events(verdict);
CREATE INDEX idx_triage_processed ON triage_events(processed_at);
