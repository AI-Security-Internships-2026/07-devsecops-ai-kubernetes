-- CVE Intelligence Database schema (SQLite, stdlib).

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    cvss_score      REAL DEFAULT 0.0,
    severity        TEXT,
    published       TEXT,             -- ISO date from the feed
    last_modified   TEXT,             -- ISO date from the feed
    epss_score      REAL,             -- may be NULL for brand-new CVEs (EPSS lag)
    epss_percentile REAL,
    in_kev          INTEGER DEFAULT 0,
    source          TEXT,             -- nvd | osv | ...
    first_seen      TEXT DEFAULT (datetime('now'))   -- when WE ingested it
);

CREATE TABLE IF NOT EXISTS affected_packages (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id             TEXT NOT NULL,
    ecosystem          TEXT,          -- debian | go | pypi | npm | cpe | ...
    package_name       TEXT,
    purl               TEXT,          -- package URL if known (OSV)
    version_introduced TEXT,
    version_fixed      TEXT,
    raw_range          TEXT,          -- original range string for auditing
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE TABLE IF NOT EXISTS exploits (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id   TEXT NOT NULL,
    source   TEXT,                    -- exploitdb | metasploit
    ref      TEXT,
    UNIQUE (cve_id, source, ref)
);

CREATE TABLE IF NOT EXISTS sboms (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    image        TEXT NOT NULL,
    generated_at TEXT DEFAULT (datetime('now')),
    path         TEXT,
    UNIQUE (image)
);

CREATE TABLE IF NOT EXISTS sbom_packages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id      INTEGER NOT NULL,
    package_name TEXT,
    version      TEXT,
    purl         TEXT,
    ecosystem    TEXT,
    FOREIGN KEY (sbom_id) REFERENCES sboms(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id             TEXT NOT NULL,
    image              TEXT NOT NULL,
    package_name       TEXT,
    created_at         TEXT DEFAULT (datetime('now')),
    reason             TEXT,
    priority           TEXT,          -- FRESH-CRITICAL | FRESH-WATCH | ...
    needs_verification INTEGER DEFAULT 1,
    status             TEXT DEFAULT 'new',   -- new | verified | dismissed
    UNIQUE (cve_id, image, package_name)
);

CREATE INDEX IF NOT EXISTS idx_affected_pkg_name ON affected_packages(package_name);
CREATE INDEX IF NOT EXISTS idx_affected_cve      ON affected_packages(cve_id);
CREATE INDEX IF NOT EXISTS idx_sbom_pkg_name     ON sbom_packages(package_name);
CREATE INDEX IF NOT EXISTS idx_cves_first_seen   ON cves(first_seen);
