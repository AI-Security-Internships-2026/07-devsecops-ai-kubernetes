"""
NVD API 2.0 poller.

Pulls CVEs modified within a recent window and stores them in the CVE intelligence DB.

NVD 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limit: ~5 requests / 30s without a key (50 with a free key).
"""

import os
import time
from datetime import datetime, timedelta, timezone

import httpx

from src.database import db

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD max resultsPerPage


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    """Best CVSS score+severity: prefer v3.1, then v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData", {})
            return float(data.get("baseScore", 0.0)), data.get("baseSeverity", "UNKNOWN")
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        data = arr[0].get("cvssData", {})
        return float(data.get("baseScore", 0.0)), arr[0].get("baseSeverity", "UNKNOWN")
    return 0.0, "UNKNOWN"


def _extract_affected(configurations: list) -> list[dict]:
    """Pull affected products from CPE match nodes (coarse, ecosystem='cpe')."""
    affected = []
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")  # cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                product = parts[4] if len(parts) > 4 else ""
                if not product or product == "*":
                    continue
                affected.append({
                    "ecosystem": "cpe",
                    "package_name": product,
                    "purl": None,
                    "version_introduced": match.get("versionStartIncluding")
                    or match.get("versionStartExcluding"),
                    "version_fixed": match.get("versionEndExcluding"),
                    "raw_range": criteria,
                })
    return affected


def parse_nvd_items(data: dict) -> list[dict]:
    """Convert an NVD 2.0 response into our CVE dicts."""
    out = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id.startswith("CVE-"):
            continue
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        score, severity = _extract_cvss(cve.get("metrics", {}))
        out.append({
            "cve_id": cve_id,
            "description": desc[:1000],
            "cvss_score": score,
            "severity": severity,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "epss_score": None,
            "epss_percentile": None,
            "in_kev": 1 if cve.get("cisaExploitAdd") else 0,
            "source": "nvd",
            "affected": _extract_affected(cve.get("configurations", [])),
        })
    return out


def fetch_nvd(hours: int = 24, api_key: str | None = None) -> list[dict]:
    """Fetch CVEs modified in the last `hours`. Returns parsed CVE dicts."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    headers = {"apiKey": api_key} if api_key else {}

    all_items: list[dict] = []
    start_index = 0
    while True:
        params = {
            "lastModStartDate": start.strftime(fmt),
            "lastModEndDate": now.strftime(fmt),
            "resultsPerPage": PAGE_SIZE,
            "startIndex": start_index,
        }
        print(f"[*] NVD query (startIndex={start_index}) ...")
        resp = httpx.get(NVD_URL, params=params, headers=headers, timeout=60.0)
        resp.raise_for_status()
        data = resp.json()

        all_items.extend(parse_nvd_items(data))
        total = data.get("totalResults", 0)
        start_index += PAGE_SIZE
        if start_index >= total:
            break
        time.sleep(6 if not api_key else 1)  # respect rate limit

    return all_items


def poll_nvd(hours: int = 24) -> int:
    """Fetch recent NVD CVEs and store them. Returns the number ingested."""
    db.init_db()
    api_key = os.getenv("NVD_API_KEY")  # optional
    try:
        items = fetch_nvd(hours=hours, api_key=api_key)
    except Exception as e:
        print(f"[!] NVD fetch failed: {e}")
        return 0

    with db.get_conn() as conn:
        for item in items:
            db.upsert_cve(conn, item)
            db.clear_affected_packages(conn, item["cve_id"])
            for pkg in item.get("affected", []):
                db.add_affected_package(conn, item["cve_id"], pkg)
        conn.commit()

    print(f"[+] NVD: ingested {len(items)} CVEs (last {hours}h)")
    return len(items)
