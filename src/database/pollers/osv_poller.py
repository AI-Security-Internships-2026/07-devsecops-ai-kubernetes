"""
OSV.dev poller.

OSV is package-centric: given the packages in our stored SBOMs, it returns the
known vulnerabilities affecting them with precise version ranges (purl-native).

OSV query API: POST https://api.osv.dev/v1/query
"""

import httpx

from src.database import db

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def purl_without_version(purl: str) -> str:
    """Strip the '@version' suffix from a purl (OSV wants purl + version separately)."""
    if not purl:
        return ""
    return purl.split("@", 1)[0]


def choose_cve_id(vuln: dict) -> str:
    """Prefer a CVE alias; fall back to the OSV id."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def parse_osv_vuln(vuln: dict) -> dict:
    """Convert one OSV vuln object into our CVE dict (pure)."""
    cve_id = choose_cve_id(vuln)
    affected = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        for rng in aff.get("ranges", []):
            introduced = fixed = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
            affected.append({
                "ecosystem": pkg.get("ecosystem", ""),
                "package_name": pkg.get("name", ""),
                "purl": pkg.get("purl"),
                "version_introduced": introduced,
                "version_fixed": fixed,
                "raw_range": rng.get("type", ""),
            })
        # Some entries list explicit versions with no ranges
        if not aff.get("ranges") and aff.get("versions"):
            affected.append({
                "ecosystem": pkg.get("ecosystem", ""),
                "package_name": pkg.get("name", ""),
                "purl": pkg.get("purl"),
                "version_introduced": None,
                "version_fixed": None,
                "raw_range": "explicit-versions:" + ",".join(aff["versions"][:20]),
            })

    return {
        "cve_id": cve_id,
        "description": (vuln.get("summary") or vuln.get("details") or "")[:1000],
        "cvss_score": 0.0,
        "severity": None,
        "published": vuln.get("published"),
        "last_modified": vuln.get("modified"),
        "epss_score": None,
        "epss_percentile": None,
        "in_kev": 0,
        "source": "osv",
        "affected": affected,
    }


def _query_osv(purl: str, version: str | None) -> list[dict]:
    body: dict = {"package": {"purl": purl_without_version(purl)}}
    if version:
        body["version"] = version
    resp = httpx.post(OSV_QUERY_URL, json=body, timeout=30.0)
    resp.raise_for_status()
    return resp.json().get("vulns", [])


def poll_osv(max_packages: int = 500) -> int:
    """
    Query OSV for every distinct purl in our stored SBOMs; store the CVEs +
    affected ranges. Returns the number of vulnerabilities ingested.
    """
    db.init_db()

    with db.get_conn() as conn:
        rows = db.all_sbom_packages(conn)

    # distinct purls (with a representative version)
    seen: dict[str, str] = {}
    for r in rows:
        purl = r["purl"]
        if purl and purl_without_version(purl) not in seen:
            seen[purl_without_version(purl)] = r["version"] or ""

    if not seen:
        print("[*] OSV: no SBOM packages with purls yet — generate an SBOM first "
              "(python run.py scan ... or the sbom module).")
        return 0

    purls = list(seen.items())[:max_packages]
    print(f"[*] OSV: querying {len(purls)} distinct packages...")

    ingested = 0
    with db.get_conn() as conn:
        for base_purl, version in purls:
            try:
                vulns = _query_osv(base_purl, version)
            except Exception as e:
                print(f"[!] OSV query failed for {base_purl}: {e}")
                continue
            for vuln in vulns:
                item = parse_osv_vuln(vuln)
                if not item["cve_id"]:
                    continue
                db.upsert_cve(conn, item)
                db.clear_affected_packages(conn, item["cve_id"])
                for pkg in item["affected"]:
                    db.add_affected_package(conn, item["cve_id"], pkg)
                ingested += 1
        conn.commit()

    print(f"[+] OSV: ingested {ingested} vulnerability records")
    return ingested
