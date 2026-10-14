"""SQLite database schema and DDL definitions for Purple Team Cyber Range."""

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    technique_ids_json TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    playbook_id TEXT,
    status TEXT NOT NULL,
    operator TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    total_techniques INTEGER NOT NULL DEFAULT 0,
    detected_count INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    missed_count INTEGER NOT NULL DEFAULT 0,
    detection_coverage_rate REAL NOT NULL DEFAULT 0.0,
    mean_alert_latency_seconds REAL NOT NULL DEFAULT 0.0,
    FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS emulation_steps (
    execution_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    target_host TEXT NOT NULL,
    command_executed TEXT NOT NULL,
    stdout TEXT NOT NULL,
    stderr TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    status TEXT NOT NULL,
    process_pid INTEGER,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_ms REAL NOT NULL,
    cleanup_executed INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_steps_campaign_id ON emulation_steps(campaign_id);
CREATE INDEX IF NOT EXISTS idx_steps_technique_id ON emulation_steps(technique_id);

CREATE TABLE IF NOT EXISTS detection_alerts (
    alert_id TEXT PRIMARY KEY,
    sensor_name TEXT NOT NULL,
    technique_id TEXT,
    timestamp TEXT NOT NULL,
    host TEXT NOT NULL,
    process_name TEXT,
    process_pid INTEGER,
    command_line TEXT,
    alert_signature TEXT NOT NULL,
    severity TEXT NOT NULL,
    raw_log_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON detection_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON detection_alerts(host);
CREATE INDEX IF NOT EXISTS idx_alerts_technique_id ON detection_alerts(technique_id);

CREATE TABLE IF NOT EXISTS detection_evidences (
    evidence_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    matched_alerts_json TEXT NOT NULL,
    detection_latency_seconds REAL,
    matched_at TEXT NOT NULL,
    notes TEXT NOT NULL,
    FOREIGN KEY (execution_id) REFERENCES emulation_steps(execution_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidences_execution_id ON detection_evidences(execution_id);

CREATE TABLE IF NOT EXISTS matrix_heatmaps (
    report_id TEXT PRIMARY KEY,
    campaign_id TEXT,
    generated_at TEXT NOT NULL,
    total_techniques INTEGER NOT NULL,
    detected_count INTEGER NOT NULL,
    blocked_count INTEGER NOT NULL,
    missed_count INTEGER NOT NULL,
    detection_coverage_rate REAL NOT NULL,
    tactic_summaries_json TEXT NOT NULL,
    cells_json TEXT NOT NULL,
    blind_spots_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_heatmaps_campaign_id ON matrix_heatmaps(campaign_id);

CREATE TABLE IF NOT EXISTS sigma_rules (
    rule_id TEXT PRIMARY KEY,
    technique_id TEXT,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    description TEXT NOT NULL,
    author TEXT NOT NULL,
    date TEXT NOT NULL,
    level TEXT NOT NULL,
    logsource_json TEXT NOT NULL,
    detection_json TEXT NOT NULL,
    condition TEXT NOT NULL,
    falsepositives_json TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    references_json TEXT NOT NULL,
    yaml_content TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sigma_technique_id ON sigma_rules(technique_id);
"""
