"""
Bulk CVSS index from NVD, for the publication dataset (issue #21).

Why a bulk index rather than per-CVE lookups
--------------------------------------------
The dataset needs a CVSS score for every CVE it evaluates, because the CVSS-only
baseline ranks on it. Querying NVD once per CVE would be tens of thousands of requests
against a 5-per-30-seconds limit. Paginating the whole catalog is ~150 requests, so one
bulk pass is both faster and gives complete coverage — which matters, because sampling
only the CVEs we could conveniently look up would bias the comparison toward whatever
NVD answers quickly.

Only four fields are kept per CVE (id, score, severity, version, published date); the
full NVD records are streamed and discarded, so a multi-gigabyte catalog compresses to a
small CSV that can be cached, hashed and rebuilt.

Documented approximation
------------------------
NVD does not publish per-date CVSS archives the way EPSS does, so the *current* base
score is used as a stand-in for the score at snapshot time. Base scores are assigned at
publication and revised rarely, so this is a reasonable approximation — but it is an
approximation, and issue #21 requires approximated inputs to be marked as such rather
than presented as point-in-time truth. `published` is retained so CVEs that did not yet
exist at a snapshot can be excluded outright, which is the one temporal error this would
otherwise introduce.
"""

import csv
import os
import time
from datetime import date, datetime
from pathlib import Path

import httpx

from src.database.pollers.nvd_poller import _extract_cvss
from src.dataset.sources import _cache_path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000                      # NVD maximum
FIELDS = ["cve_id", "cvss_score", "cvss_severity", "cvss_version", "published"]


def index_path() -> Path:
    return _cache_path("nvd_cvss_index.csv")


def _progress_path() -> Path:
    return _cache_path("nvd_cvss_index.progress")


def _cvss_version(metrics: dict) -> str:
    """Which CVSS generation the score came from — needed to interpret the value."""
    for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                       ("cvssMetricV2", "2.0")):
        if metrics.get(key):
            return label
    return "none"


def build_index(api_key: str | None = None, resume: bool = True,
                max_pages: int | None = None) -> Path:
    """
    Page through the NVD catalog and write a compact CVSS index.

    Resumable: progress is checkpointed per page, so an interrupted run continues where
    it stopped rather than restarting a 150-request download. Set `resume=False` to
    rebuild from scratch.
    """
    dest, progress = index_path(), _progress_path()
    api_key = api_key or os.getenv("NVD_API_KEY")

    start_index = 0
    if resume and dest.exists() and progress.exists():
        try:
            start_index = int(progress.read_text(encoding="utf-8").strip())
            print(f"[*] Resuming NVD index from startIndex={start_index:,}")
        except ValueError:
            start_index = 0
    elif not resume:
        dest.unlink(missing_ok=True)
        progress.unlink(missing_ok=True)

    mode = "a" if start_index and dest.exists() else "w"
    headers = {"apiKey": api_key} if api_key else {}
    # Without a key NVD allows ~5 requests per 30s; the documented courtesy delay is 6s.
    delay = 1.0 if api_key else 6.0
    if not api_key:
        print("[*] No NVD_API_KEY set — throttling to 6s/request (~15 min for a full "
              "index). A free key from nvd.nist.gov reduces this to ~3 min.")

    pages = 0
    total = None
    with open(dest, mode, newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        if mode == "w":
            writer.writeheader()

        while True:
            params = {"resultsPerPage": PAGE_SIZE, "startIndex": start_index}
            try:
                r = httpx.get(NVD_URL, params=params, headers=headers, timeout=120.0)
                r.raise_for_status()
                payload = r.json()
            except Exception as e:
                # A partial index is still usable and resumable, so stop rather than
                # discard what has already been fetched.
                print(f"[!] NVD request failed at startIndex={start_index}: {e}")
                print(f"[*] Partial index kept; re-run to resume.")
                break

            total = payload.get("totalResults", 0)
            items = payload.get("vulnerabilities", []) or []
            if not items:
                break

            for item in items:
                cve = item.get("cve", {})
                cve_id = (cve.get("id") or "").strip().upper()
                if not cve_id.startswith("CVE-"):
                    continue
                metrics = cve.get("metrics", {}) or {}
                score, severity = _extract_cvss(metrics)
                writer.writerow({
                    "cve_id": cve_id,
                    "cvss_score": score,
                    "cvss_severity": severity,
                    "cvss_version": _cvss_version(metrics),
                    "published": (cve.get("published") or "")[:10],
                })
            fh.flush()

            start_index += len(items)
            progress.write_text(str(start_index), encoding="utf-8")
            pages += 1
            pct = (start_index / total * 100) if total else 0
            print(f"[*] NVD {start_index:,}/{total:,} ({pct:.1f}%)")

            if start_index >= total or (max_pages and pages >= max_pages):
                break
            time.sleep(delay)

    print(f"[+] CVSS index: {dest} ({dest.stat().st_size:,} bytes)")
    return dest


def load_index() -> dict[str, dict]:
    """
    {cve_id: {"cvss_score", "cvss_severity", "cvss_version", "published"}}.

    Raises if the index has not been built — silently returning an empty index would
    produce a dataset where every CVSS score is zero, which would look like a real
    result rather than a missing input.
    """
    path = index_path()
    if not path.exists():
        raise FileNotFoundError(
            f"CVSS index not found at {path}. Build it with:\n"
            f"    python scripts/build_dataset.py --cvss-index")
    out: dict[str, dict] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cve = (row.get("cve_id") or "").strip().upper()
            if not cve:
                continue
            try:
                score = float(row.get("cvss_score") or 0.0)
            except ValueError:
                score = 0.0
            out[cve] = {
                "cvss_score": score,
                "cvss_severity": (row.get("cvss_severity") or "UNKNOWN").upper(),
                "cvss_version": row.get("cvss_version") or "none",
                "published": row.get("published") or "",
            }
    return out


def published_before(record: dict, snapshot: date) -> bool:
    """
    Whether a CVE existed at snapshot time.

    A CVE published after T could not have been prioritized at T, so including it would
    be look-ahead leakage of a different kind: not a leaked label, but a leaked record.
    Missing publication dates are treated as not-yet-published, which is the
    conservative choice — it shrinks the population rather than inflating it.
    """
    raw = (record or {}).get("published") or ""
    if not raw:
        return False
    try:
        return datetime.strptime(raw[:10], "%Y-%m-%d").date() <= snapshot
    except ValueError:
        return False
