"""
Central path configuration.

Paths are resolved relative to the repository root (derived from this file's
location), NOT the current working directory — so scripts work no matter where
they're invoked from.
"""

from pathlib import Path

# repo root = two levels up from this file (src/config.py -> src -> repo root)
ROOT = Path(__file__).resolve().parent.parent

# Scan / enrichment / triage outputs (existing convention)
RESULTS_DIR = ROOT / "experiments" / "results"

# CVE intelligence database + SBOM storage (Phase 2)
DATA_DIR = ROOT / "data"
SBOM_DIR = DATA_DIR / "sboms"
DB_PATH = DATA_DIR / "cve_intel.db"
SCHEMA_PATH = ROOT / "src" / "database" / "schema.sql"

# Cached feeds (Exploit-DB CSV, etc.)
CACHE_DIR = DATA_DIR / "cache"


def ensure_dirs() -> None:
    """Create the runtime directories if they don't exist."""
    for d in (RESULTS_DIR, DATA_DIR, SBOM_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)
