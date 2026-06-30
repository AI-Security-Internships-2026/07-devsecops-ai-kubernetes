"""
EPSS Client Module
Fetches Exploit Prediction Scoring System (EPSS) scores for CVEs.

The EPSS API (https://api.first.org/data/v1/epss) provides daily-updated
exploit probability scores (0-1) for all published CVEs.

Usage:
    python src/epss_client.py <trivy_json_file>
    python src/epss_client.py experiments/results/trivy_nginx_latest.json
"""

import json
import sys
from pathlib import Path

import httpx


EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # EPSS API accepts up to 100 CVEs per request
OUTPUT_DIR = Path("experiments/results")


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs from the FIRST.org API.

    Args:
        cve_ids: List of CVE IDs (e.g., ["CVE-2023-1234", "CVE-2024-5678"])

    Returns:
        Dict mapping CVE ID → {"epss": float, "percentile": float}
    """
    scores = {}

    for i in range(0, len(cve_ids), BATCH_SIZE):
        batch = cve_ids[i:i + BATCH_SIZE]
        cve_param = ",".join(batch)

        print(f"[*] Fetching EPSS scores for batch {i // BATCH_SIZE + 1} ({len(batch)} CVEs)...")

        try:
            response = httpx.get(
                EPSS_API_URL,
                params={"cve": cve_param},
                timeout=30.0,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            print(f"[!] API error: {e.response.status_code} — {e.response.text[:200]}")
            continue
        except httpx.RequestError as e:
            print(f"[!] Connection error: {e}")
            continue

        data = response.json()

        for entry in data.get("data", []):
            cve_id = entry.get("cve", "")
            scores[cve_id] = {
                "epss": float(entry.get("epss", 0.0)),
                "percentile": float(entry.get("percentile", 0.0)),
            }

    return scores


def load_trivy_cves(trivy_json_path: str) -> list[dict]:
    """
    Load CVEs from a Trivy JSON output file.

    Returns:
        List of CVE dicts with id, severity, cvss_score, package, etc.
    """
    path = Path(trivy_json_path)
    if not path.exists():
        print(f"[!] File not found: {trivy_json_path}")
        sys.exit(1)

    scan_data = json.loads(path.read_text())
    cves = []

    results = scan_data.get("Results", [])
    for target in results:
        vulns = target.get("Vulnerabilities") or []
        for vuln in vulns:
            cve_id = vuln.get("VulnerabilityID", "")
            if cve_id.startswith("CVE-"):
                cves.append({
                    "cve_id": cve_id,
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "title": vuln.get("Title", ""),
                })

    return cves


def enrich_with_epss(cves: list[dict], epss_scores: dict[str, dict]) -> list[dict]:
    """
    Merge EPSS scores into CVE findings.

    Returns:
        Enriched CVE list sorted by EPSS score (highest first)
    """
    for cve in cves:
        cve_id = cve["cve_id"]
        if cve_id in epss_scores:
            cve["epss_score"] = epss_scores[cve_id]["epss"]
            cve["epss_percentile"] = epss_scores[cve_id]["percentile"]
        else:
            cve["epss_score"] = 0.0
            cve["epss_percentile"] = 0.0

    return sorted(cves, key=lambda x: x["epss_score"], reverse=True)


def print_enriched_report(enriched_cves: list[dict]) -> None:
    """Print a formatted report showing EPSS-enriched findings."""
    print(f"\n{'='*90}")
    print("EPSS-ENRICHED VULNERABILITY REPORT")
    print(f"{'='*90}")
    print(
        f"{'CVE ID':<18} "
        f"{'Severity':<10} "
        f"{'CVSS':<6} "
        f"{'EPSS':<8} "
        f"{'Percentile':<12} "
        f"{'Package':<20} "
        f"{'Priority':<10}"
    )
    print("-" * 90)

    for cve in enriched_cves[:20]:
        # Simple priority logic: EPSS > 0.1 = HIGH, > 0.01 = MEDIUM, else LOW
        epss = cve["epss_score"]
        if epss >= 0.1:
            priority = "CRITICAL"
        elif epss >= 0.01:
            priority = "HIGH"
        elif epss >= 0.001:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        print(
            f"{cve['cve_id']:<18} "
            f"{cve['severity']:<10} "
            f"{cve['cvss_score']:<6.1f} "
            f"{cve['epss_score']:<8.4f} "
            f"{cve['epss_percentile']:<12.4f} "
            f"{cve['package'][:19]:<20} "
            f"{priority:<10}"
        )

    # Stats
    total = len(enriched_cves)
    high_epss = sum(1 for c in enriched_cves if c["epss_score"] >= 0.1)
    med_epss = sum(1 for c in enriched_cves if 0.01 <= c["epss_score"] < 0.1)
    low_epss = sum(1 for c in enriched_cves if c["epss_score"] < 0.01)

    print(f"\n{'='*90}")
    print(f"TRIAGE SUMMARY ({total} total CVEs)")
    print(f"{'='*90}")
    print(f"  CRITICAL priority (EPSS ≥ 0.1)  : {high_epss:>4} ({high_epss/max(total,1)*100:.1f}%) — likely to be exploited")
    print(f"  HIGH priority (EPSS 0.01–0.1)    : {med_epss:>4} ({med_epss/max(total,1)*100:.1f}%) — moderate exploit risk")
    print(f"  LOW priority (EPSS < 0.01)       : {low_epss:>4} ({low_epss/max(total,1)*100:.1f}%) — unlikely to be exploited")
    print(f"{'='*90}")
    print(f"\n[*] Alert reduction: {low_epss/max(total,1)*100:.1f}% of findings are LOW priority (safe to defer)")
    print(f"[*] Focus on: {high_epss + med_epss} out of {total} CVEs ({(high_epss+med_epss)/max(total,1)*100:.1f}%)")


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/epss_client.py <trivy_json_file>")
        print("Example: python src/epss_client.py experiments/results/trivy_nginx_latest.json")
        sys.exit(1)

    trivy_json_path = sys.argv[1]

    # Step 1: Load CVEs from Trivy output
    print(f"[*] Loading Trivy results from: {trivy_json_path}")
    cves = load_trivy_cves(trivy_json_path)
    print(f"[+] Found {len(cves)} CVEs in scan results")

    if not cves:
        print("[!] No CVEs found in the Trivy output.")
        sys.exit(0)

    # Step 2: Fetch EPSS scores
    unique_cve_ids = list(set(c["cve_id"] for c in cves))
    print(f"[*] Fetching EPSS scores for {len(unique_cve_ids)} unique CVEs...")
    epss_scores = fetch_epss_scores(unique_cve_ids)
    print(f"[+] Got EPSS scores for {len(epss_scores)} CVEs")

    # Step 3: Enrich and sort
    enriched = enrich_with_epss(cves, epss_scores)

    # Step 4: Print report
    print_enriched_report(enriched)

    # Step 5: Save enriched output
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    input_name = Path(trivy_json_path).stem
    output_path = OUTPUT_DIR / f"epss_enriched_{input_name}.json"
    output_path.write_text(json.dumps(enriched, indent=2))
    print(f"\n[+] Enriched results saved to: {output_path}")


if __name__ == "__main__":
    main()
