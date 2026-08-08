-- Exposure initial schema (schema version 1).
-- Forward-only migrations. Never edit an applied migration; add a new one.

CREATE TABLE subjects (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    -- Non-sensitive structured profile (names, locations, employers,
    -- usernames, personal_domains) as JSON. Sensitive identifiers live in
    -- subject_identifiers, encrypted.
    profile     TEXT NOT NULL
);

CREATE TABLE subject_identifiers (
    id          TEXT PRIMARY KEY,
    subject_id  TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,            -- EMAIL | PHONE
    display     TEXT NOT NULL,            -- masked form, safe to show
    value_enc   BLOB NOT NULL,           -- Fernet-encrypted raw value
    UNIQUE (subject_id, kind, display)
);
CREATE INDEX ix_identifiers_subject ON subject_identifiers(subject_id);

CREATE TABLE scans (
    id          TEXT PRIMARY KEY,
    subject_id  TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,            -- RUNNING | COMPLETE | INCOMPLETE | CANCELLED | ERROR
    stats       TEXT NOT NULL DEFAULT '{}',
    error       TEXT
);
CREATE INDEX ix_scans_subject ON scans(subject_id);

CREATE TABLE sources (
    id                 TEXT PRIMARY KEY,
    scan_id            TEXT REFERENCES scans(id) ON DELETE CASCADE,
    url                TEXT NOT NULL,
    canonical_url      TEXT NOT NULL,
    registrable_domain TEXT NOT NULL,
    title              TEXT,
    retrieved_at       TEXT,
    http_status        INTEGER,
    content_type       TEXT,
    content_hash       TEXT,
    status             TEXT NOT NULL
);
CREATE INDEX ix_sources_scan ON sources(scan_id);
CREATE INDEX ix_sources_canonical ON sources(canonical_url);

CREATE TABLE observations (
    id                TEXT PRIMARY KEY,
    source_id         TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    type              TEXT NOT NULL,
    value_normalized  TEXT NOT NULL,
    display_value     TEXT NOT NULL,
    evidence_snippet  TEXT NOT NULL,
    extractor         TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    is_sensitive      INTEGER NOT NULL DEFAULT 0,
    observed_at       TEXT NOT NULL
);
CREATE INDEX ix_observations_source ON observations(source_id);

CREATE TABLE matches (
    id                 TEXT PRIMARY KEY,
    source_id          TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    subject_id         TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    state              TEXT NOT NULL,
    confidence         REAL NOT NULL,
    supporting         TEXT NOT NULL DEFAULT '[]',
    contradicting      TEXT NOT NULL DEFAULT '[]',
    resolution_version TEXT NOT NULL,
    user_overridden    INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    UNIQUE (source_id, subject_id)
);
CREATE INDEX ix_matches_subject ON matches(subject_id);

CREATE TABLE findings (
    id                        TEXT PRIMARY KEY,
    subject_id                TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    source_id                 TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    category                  TEXT NOT NULL,
    sensitivity               TEXT NOT NULL,
    discoverability           TEXT NOT NULL,
    misuse_potential          TEXT NOT NULL,
    persistence               TEXT NOT NULL,
    overall_priority          TEXT NOT NULL,
    assessment_confidence     REAL NOT NULL,
    identity_confidence       REAL NOT NULL,
    match_state               TEXT NOT NULL,
    explanation_codes         TEXT NOT NULL DEFAULT '[]',
    summary                   TEXT NOT NULL DEFAULT '',
    observation_ids           TEXT NOT NULL DEFAULT '[]',
    assessment_policy_version  TEXT NOT NULL DEFAULT '',
    created_at                TEXT NOT NULL
);
CREATE INDEX ix_findings_subject ON findings(subject_id);
CREATE INDEX ix_findings_source ON findings(source_id);

CREATE TABLE remediation_cases (
    id                TEXT PRIMARY KEY,
    finding_id        TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    route             TEXT NOT NULL,
    registry_route_id TEXT,
    state             TEXT NOT NULL,
    opened_at         TEXT NOT NULL,
    submitted_at      TEXT,
    last_checked_at   TEXT,
    verification      TEXT,
    note              TEXT
);
CREATE INDEX ix_cases_finding ON remediation_cases(finding_id);

CREATE TABLE case_events (
    id       TEXT PRIMARY KEY,
    case_id  TEXT NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
    at       TEXT NOT NULL,
    kind     TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_case_events_case ON case_events(case_id);

-- Provider settings NEVER store secrets (spec section 21). API keys live in
-- the OS keyring or the encrypted secrets file only.
CREATE TABLE provider_settings (
    id       TEXT PRIMARY KEY,          -- provider id, e.g. 'brave'
    kind     TEXT NOT NULL,             -- 'search' | 'ai'
    enabled  INTEGER NOT NULL DEFAULT 0,
    config   TEXT NOT NULL DEFAULT '{}'
);
