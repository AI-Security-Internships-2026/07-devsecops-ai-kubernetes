"""
Point-in-time vulnerability signal sources for the publication dataset (issue #21).

The evaluation has to answer "given only what was knowable on date T, which
vulnerabilities would each method have prioritized?" — so every predictive feature must
be read as it stood on T, never as it stands today. Using today's EPSS score to evaluate
a decision that would have been made a year ago is look-ahead leakage, and it is the
single defect that would invalidate the whole evaluation.

Two sources make that practical:

* **EPSS** publishes a full daily score file, archived back to 2021-04-14, so
  "EPSS as it was on T" is a download rather than a reconstruction.
* **KEV** records a `dateAdded` per entry, so one current catalog yields both the
  snapshot state (`dateAdded <= T`) and the future outcome (`T < dateAdded <= T+N`).
  No historical KEV archive is required.

Everything is cached to disk and hashed. The hash goes into the dataset manifest so a
reader can tell whether a rebuild used the same inputs, which is what issue #26 asks for
when the raw data cannot be redistributed.
"""

import csv
import gzip
import hashlib
import io
import json
from datetime import date, datetime, timedelta
from pathlib import Path

import httpx

from src import config

# Daily EPSS score files. The archive begins here; earlier snapshots are not available.
EPSS_DAILY_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
EPSS_ARCHIVE_START = date(2021, 4, 14)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE = config.CACHE_DIR / "dataset"


def _cache_path(name: str) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    return CACHE / name


def sha256(path: Path) -> str:
    """Content hash of a cached source file, for the reproducibility manifest."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, timeout: float = 120.0) -> Path:
    """Fetch to `dest` unless already cached. Cached files are never re-fetched."""
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    print(f"[*] Downloading {url}")
    with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as r:
        r.raise_for_status()
        tmp = dest.with_suffix(dest.suffix + ".part")
        with open(tmp, "wb") as fh:
            for chunk in r.iter_bytes():
                fh.write(chunk)
        tmp.replace(dest)          # atomic, so an interrupted download is never cached
    print(f"[+] Cached {dest.name} ({dest.stat().st_size:,} bytes)")
    return dest


# ---------------------------------------------------------------------- EPSS

def epss_snapshot_path(snapshot: date) -> Path:
    return _cache_path(f"epss_scores-{snapshot.isoformat()}.csv.gz")


def fetch_epss_snapshot(snapshot: date) -> Path:
    """Download (or reuse) the EPSS score file published for `snapshot`."""
    if snapshot < EPSS_ARCHIVE_START:
        raise ValueError(
            f"EPSS daily archive starts {EPSS_ARCHIVE_START.isoformat()}; "
            f"{snapshot.isoformat()} predates it")
    if snapshot >= date.today():
        raise ValueError(
            f"snapshot {snapshot.isoformat()} is not in the past — a snapshot needs its "
            f"outcome window to have already elapsed")
    return _download(EPSS_DAILY_URL.format(date=snapshot.isoformat()),
                     epss_snapshot_path(snapshot))


def load_epss_snapshot(snapshot: date) -> dict[str, dict]:
    """
    EPSS scores as published on `snapshot`: {cve_id: {"epss", "percentile"}}.

    The file is a gzipped CSV whose first line is a `#`-prefixed model/version banner,
    which is skipped. That banner also names the EPSS model version, captured separately
    by `epss_model_version` — coverage figures are version-specific, so the paper has to
    state which model produced the scores.
    """
    path = fetch_epss_snapshot(snapshot)
    out: dict[str, dict] = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        text = io.StringIO("".join(line for line in fh if not line.startswith("#")))
        for row in csv.DictReader(text):
            cve = (row.get("cve") or "").strip().upper()
            if not cve.startswith("CVE-"):
                continue
            try:
                out[cve] = {
                    "epss": float(row.get("epss") or 0.0),
                    "percentile": float(row.get("percentile") or 0.0),
                }
            except ValueError:
                continue          # malformed row; the archive is large, skip quietly
    return out


def epss_model_version(snapshot: date) -> str:
    """
    The model version banner from a snapshot file, e.g. 'v2023.03.01'.

    Recorded in the manifest because EPSS has been through several model generations
    (v1-v4) with materially different score distributions, so a score is only
    interpretable alongside the model that produced it.
    """
    path = fetch_epss_snapshot(snapshot)
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        first = fh.readline().strip()
    if not first.startswith("#"):
        return "unknown"
    for part in first.lstrip("#").split(","):
        part = part.strip()
        if part.startswith("model_version:"):
            return part.split(":", 1)[1].strip()
    return first.lstrip("#").strip()


# ----------------------------------------------------------------------- KEV

def kev_path() -> Path:
    return _cache_path("kev_catalog.json")


def fetch_kev_catalog(refresh: bool = False) -> Path:
    """
    Download (or reuse) the current KEV catalog.

    Unlike EPSS this is a single current snapshot, and the dataset's future labels are
    derived from it, so the download date bounds how far forward outcomes can be
    observed — recorded in the manifest as `kev_downloaded`.
    """
    dest = kev_path()
    if refresh and dest.exists():
        dest.unlink()
    return _download(KEV_URL, dest, timeout=60.0)


def load_kev_dates(refresh: bool = False) -> dict[str, date]:
    """
    {cve_id: date_added} for the whole KEV catalog.

    `dateAdded` is what makes temporal labelling possible from a single download: it
    separates "already known exploited at T" from "became known exploited after T",
    and only the latter is a legitimate prediction target.
    """
    path = fetch_kev_catalog(refresh=refresh)
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, date] = {}
    for entry in data.get("vulnerabilities", []):
        cve = (entry.get("cveID") or "").strip().upper()
        raw = entry.get("dateAdded") or ""
        if not cve or not raw:
            continue
        try:
            out[cve] = datetime.strptime(raw[:10], "%Y-%m-%d").date()
        except ValueError:
            continue
    return out


def kev_catalog_date() -> str | None:
    """The catalog's own release date, for the manifest."""
    path = kev_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data.get("catalogVersion") or data.get("dateReleased")


# ------------------------------------------------------------------- labels

def kev_labels(kev_dates: dict[str, date], cve: str, snapshot: date,
               windows: tuple[int, ...]) -> dict:
    """
    Temporal labels for one CVE at one snapshot.

    Returns `kev_at_snapshot` plus one `later_kev_<N>d` per window. A CVE already in KEV
    at T is NOT a prediction target for that snapshot — its exploitation was already
    known, so counting it as a successful prediction would reward the method for
    reading an input it was given. Those rows are kept and flagged (`eligible` False)
    rather than dropped, so the manifest can report how many were excluded and why.
    """
    added = kev_dates.get(cve)
    at_snapshot = bool(added and added <= snapshot)
    labels = {"kev_at_snapshot": at_snapshot,
              "kev_date_added": added.isoformat() if added else None}
    for n in windows:
        horizon = snapshot + timedelta(days=n)
        labels[f"later_kev_{n}d"] = bool(
            added and not at_snapshot and snapshot < added <= horizon)
    # Eligible as a prediction target only if exploitation was not already known at T.
    labels["eligible"] = not at_snapshot
    return labels
