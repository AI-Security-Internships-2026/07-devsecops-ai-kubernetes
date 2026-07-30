"""
SQLite interface for the CVE Intelligence Database.

Uses only the stdlib `sqlite3` module. `init_db()` is idempotent (safe to call
on every run). All writes are upserts so repeated polls don't duplicate rows.
"""

import sqlite3
from pathlib import Path

from src import config


def get_conn() -> sqlite3.Connection:
    """Open a connection with row access by name and FK enforcement."""
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(schema_path: Path | None = None) -> Path:
    """Create the schema if absent. Returns the DB path."""
    schema_path = schema_path or config.SCHEMA_PATH
    sql = Path(schema_path).read_text(encoding="utf-8")
    with get_conn() as conn:
        conn.executescript(sql)
    return config.DB_PATH


# --- writes ---------------------------------------------------------------

def upsert_cve(conn: sqlite3.Connection, cve: dict) -> None:
    """Insert/update a CVE row. `cve` keys mirror the `cves` columns."""
    conn.execute(
        """
        INSERT INTO cves (cve_id, description, cvss_score, severity, published,
                          last_modified, epss_score, epss_percentile, in_kev, source)
        VALUES (:cve_id, :description, :cvss_score, :severity, :published,
                :last_modified, :epss_score, :epss_percentile, :in_kev, :source)
        ON CONFLICT(cve_id) DO UPDATE SET
            description=COALESCE(excluded.description, cves.description),
            cvss_score=COALESCE(excluded.cvss_score, cves.cvss_score),
            severity=COALESCE(excluded.severity, cves.severity),
            last_modified=COALESCE(excluded.last_modified, cves.last_modified),
            epss_score=COALESCE(excluded.epss_score, cves.epss_score),
            epss_percentile=COALESCE(excluded.epss_percentile, cves.epss_percentile),
            in_kev=MAX(cves.in_kev, excluded.in_kev)
        """,
        {
            "cve_id": cve["cve_id"],
            "description": cve.get("description"),
            "cvss_score": cve.get("cvss_score", 0.0),
            "severity": cve.get("severity"),
            "published": cve.get("published"),
            "last_modified": cve.get("last_modified"),
            "epss_score": cve.get("epss_score"),
            "epss_percentile": cve.get("epss_percentile"),
            "in_kev": 1 if cve.get("in_kev") else 0,
            "source": cve.get("source"),
        },
    )


def add_affected_package(conn: sqlite3.Connection, cve_id: str, pkg: dict) -> None:
    conn.execute(
        """
        INSERT INTO affected_packages
            (cve_id, ecosystem, package_name, purl, version_introduced, version_fixed, raw_range)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cve_id,
            pkg.get("ecosystem"),
            pkg.get("package_name"),
            pkg.get("purl"),
            pkg.get("version_introduced"),
            pkg.get("version_fixed"),
            pkg.get("raw_range"),
        ),
    )


def clear_affected_packages(conn: sqlite3.Connection, cve_id: str) -> None:
    """Remove existing affected-package rows for a CVE before re-inserting."""
    conn.execute("DELETE FROM affected_packages WHERE cve_id = ?", (cve_id,))


def insert_sbom(conn: sqlite3.Connection, image: str, path: str) -> int:
    """Insert/replace an SBOM record; return its id. Old packages are cleared."""
    cur = conn.execute(
        """
        INSERT INTO sboms (image, path, generated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(image) DO UPDATE SET path=excluded.path, generated_at=datetime('now')
        """,
        (image, path),
    )
    row = conn.execute("SELECT id FROM sboms WHERE image = ?", (image,)).fetchone()
    sbom_id = row["id"]
    conn.execute("DELETE FROM sbom_packages WHERE sbom_id = ?", (sbom_id,))
    return sbom_id


def add_sbom_package(conn: sqlite3.Connection, sbom_id: int, pkg: dict) -> None:
    conn.execute(
        "INSERT INTO sbom_packages (sbom_id, package_name, version, purl, ecosystem) VALUES (?, ?, ?, ?, ?)",
        (sbom_id, pkg.get("package_name"), pkg.get("version"), pkg.get("purl"), pkg.get("ecosystem")),
    )


def insert_alert(conn: sqlite3.Connection, alert: dict) -> None:
    conn.execute(
        """
        INSERT INTO alerts (cve_id, image, package_name, reason, priority, needs_verification)
        VALUES (:cve_id, :image, :package_name, :reason, :priority, :needs_verification)
        ON CONFLICT(cve_id, image, package_name) DO UPDATE SET
            reason=excluded.reason, priority=excluded.priority
        """,
        {
            "cve_id": alert["cve_id"],
            "image": alert["image"],
            "package_name": alert.get("package_name", ""),
            "reason": alert.get("reason"),
            "priority": alert.get("priority"),
            "needs_verification": 1 if alert.get("needs_verification", True) else 0,
        },
    )


# --- reads -----------------------------------------------------------------

def latest_cves(conn: sqlite3.Connection, hours: int = 24) -> list[sqlite3.Row]:
    """CVEs we ingested within the last `hours`."""
    return conn.execute(
        "SELECT * FROM cves WHERE first_seen >= datetime('now', ?) ORDER BY first_seen DESC",
        (f"-{int(hours)} hours",),
    ).fetchall()


def get_cve(conn: sqlite3.Connection, cve_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()


def get_affected_packages(conn: sqlite3.Connection, cve_id: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM affected_packages WHERE cve_id = ?", (cve_id,)).fetchall()


def all_sbom_packages(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Join of every stored SBOM package with its image."""
    return conn.execute(
        """
        SELECT s.image AS image, p.package_name AS package_name,
               p.version AS version, p.purl AS purl, p.ecosystem AS ecosystem
        FROM sbom_packages p JOIN sboms s ON p.sbom_id = s.id
        """
    ).fetchall()


def matchable_affected(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """affected_packages joined with their CVE metadata (for the matcher)."""
    return conn.execute(
        """
        SELECT a.cve_id AS cve_id, a.ecosystem AS ecosystem, a.package_name AS package_name,
               a.purl AS purl, a.version_introduced AS version_introduced,
               a.version_fixed AS version_fixed, a.raw_range AS raw_range,
               c.in_kev AS in_kev, c.epss_score AS epss_score, c.cvss_score AS cvss_score,
               c.severity AS severity, c.source AS source, c.first_seen AS first_seen
        FROM affected_packages a JOIN cves c ON a.cve_id = c.cve_id
        WHERE a.package_name IS NOT NULL AND a.package_name != ''
        """
    ).fetchall()


def get_alerts(conn: sqlite3.Connection, status: str | None = None) -> list[sqlite3.Row]:
    if status:
        return conn.execute("SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
    return conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()


def counts(conn: sqlite3.Connection) -> dict:
    """Quick row counts for status output."""
    tables = ["cves", "affected_packages", "exploits", "sboms", "sbom_packages", "alerts"]
    return {t: conn.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"] for t in tables}
