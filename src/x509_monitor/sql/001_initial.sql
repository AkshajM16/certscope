PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('v1', 'v2')),
    configured_concurrency INTEGER NOT NULL,
    peak_concurrency INTEGER NOT NULL,
    config_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    server_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    fingerprint_sha256 TEXT PRIMARY KEY,
    spki_sha256 TEXT NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    sans_json TEXT NOT NULL,
    serial_hex TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signature_hash TEXT,
    public_key_algorithm TEXT NOT NULL,
    public_key_size INTEGER,
    pem TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificates_spki ON certificates(spki_sha256);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    collected_at TEXT NOT NULL,
    certificate_fingerprint TEXT REFERENCES certificates(fingerprint_sha256),
    chain_fingerprints_json TEXT NOT NULL DEFAULT '[]',
    tls_version TEXT,
    cipher TEXT,
    hostname_valid INTEGER,
    trust_valid INTEGER,
    verification_error TEXT,
    latency_ms REAL NOT NULL,
    error_class TEXT,
    error_message TEXT,
    UNIQUE(scan_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL,
    UNIQUE(observation_id, category, detail)
);
