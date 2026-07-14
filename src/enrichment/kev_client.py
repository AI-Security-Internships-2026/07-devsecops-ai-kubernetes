"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

The KEV catalog lists CVEs with confirmed active exploitation. Any CVE in KEV
is treated as an automatic "Act" regardless of EPSS score.
"""

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_ids(timeout: float = 30.0) -> set[str]:
    """
    Download the CISA KEV catalog and return the set of CVE IDs.

    Returns an empty set on any network/parse error (caller degrades gracefully).
    """
    try:
        response = httpx.get(KEV_URL, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[!] Could not fetch KEV catalog: {e}")
        return set()
