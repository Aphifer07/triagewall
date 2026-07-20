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
    src_asset_snapshot_id INTEGER,
    dest_asset_snapshot_id INTEGER,
    
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
    source_type TEXT NOT NULL DEFAULT 'suricata',
    raw_line TEXT NOT NULL,
    error TEXT NOT NULL,
    failed_at TEXT NOT NULL
);

-- Canonical operator context used for a verdict. Each JSON document contains
-- the full inventory revision so later inventory edits cannot rewrite history.
CREATE TABLE IF NOT EXISTS asset_snapshots (
    id INTEGER PRIMARY KEY,
    snapshot_hash TEXT NOT NULL UNIQUE,
    asset_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Source provenance is kept in a companion table so existing triage_events
-- databases do not require a backfill or table rewrite.
CREATE TABLE IF NOT EXISTS sensor_event_context (
    triage_event_id INTEGER PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_instance TEXT,
    source_event_id TEXT,
    agent_id TEXT,
    agent_name TEXT,
    FOREIGN KEY (triage_event_id) REFERENCES triage_events(id) ON DELETE CASCADE,
    UNIQUE (source_type, source_instance, source_event_id)
);

-- SQLite treats NULL values as distinct inside a UNIQUE table constraint.
-- Normalize the optional instance for events that do carry a stable source ID
-- so adapters cannot persist the same instance-less event more than once.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sensor_event_source_identity
ON sensor_event_context (
    source_type,
    COALESCE(source_instance, ''),
    source_event_id
)
WHERE source_event_id IS NOT NULL;
