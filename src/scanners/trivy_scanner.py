"""
Trivy Scanner Module
Runs Trivy vulnerability scans on container images and captures JSON output.

Usage:
    python run.py scan <image_name>
    python -m src.scanners.trivy_scanner nginx:latest
"""

import json
import subprocess
import sys
from pathlib import Path

from src import config

OUTPUT_DIR = config.RESULTS_DIR


def scan_output_path(image: str) -> Path:
    """Default JSON output path for a scanned image."""
    safe_name = image.replace("/", "_").replace(":", "_")
    return OUTPUT_DIR / f"trivy_{safe_name}.json"


def run_trivy_scan(image: str, output_file: str | None = None) -> tuple[dict, Path]:
    """
    Run Trivy scan on a container image.

    Args:
        image: Container image name (e.g., "nginx:latest", "python:3.11-slim")
        output_file: Optional path to save JSON output

    Returns:
        (scan_results dict, output_path)
    """
    cmd = [
        "trivy",
        "image",
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        image,
    ]

    print(f"[*] Scanning image: {image}")
    print(f"[*] Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Trivy is not installed or not in PATH. "
            "Install: https://trivy.dev/docs/latest/getting-started/installation/"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Trivy scan timed out after 300 seconds.")

    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(f"Trivy scan failed: {result.stderr.strip()}")

    scan_results = json.loads(result.stdout)

    output_path = Path(output_file) if output_file else scan_output_path(image)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
    print(f"[+] Scan results saved to: {output_path}")

    return scan_results, output_path


def extract_cves(scan_results: dict) -> list[dict]:
    """
    Extract a flat list of CVEs from Trivy JSON output.

    Returns:
        List of dicts with: cve_id, severity, package, installed_version,
        fixed_version, title, description
    """
    cves = []

    results = scan_results.get("Results", [])
    for target in results:
        target_name = target.get("Target", "unknown")
        vulns = target.get("Vulnerabilities") or []

        for vuln in vulns:
            cves.append({
                "cve_id": vuln.get("VulnerabilityID", ""),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                "package": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", "")[:200],
                "target": target_name,
            })

    return cves


def print_summary(cves: list[dict]) -> None:
    """Print a summary table of findings by severity."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for cve in cves:
        sev = cve["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total = len(cves)
    print(f"\n{'='*60}")
    print(f"SCAN SUMMARY: {total} vulnerabilities found")
    print(f"{'='*60}")
    print(f"  CRITICAL : {severity_counts['CRITICAL']}")
    print(f"  HIGH     : {severity_counts['HIGH']}")
    print(f"  MEDIUM   : {severity_counts['MEDIUM']}")
    print(f"  LOW      : {severity_counts['LOW']}")
    print(f"{'='*60}")

    if cves:
        print(f"\nTop 10 most severe CVEs:")
        print(f"{'CVE ID':<20} {'Severity':<10} {'CVSS':<6} {'Package':<25} {'Fixed':<15}")
        print("-" * 76)
        sorted_cves = sorted(cves, key=lambda x: x["cvss_score"], reverse=True)
        for cve in sorted_cves[:10]:
            print(
                f"{cve['cve_id']:<20} "
                f"{cve['severity']:<10} "
                f"{cve['cvss_score']:<6.1f} "
                f"{cve['package'][:24]:<25} "
                f"{cve['fixed_version'][:14]:<15}"
            )


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py scan <image_name>")
        sys.exit(1)

    image = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    scan_results, output_path = run_trivy_scan(image, output_file)
    cves = extract_cves(scan_results)
    print_summary(cves)

    unique_cves = {c["cve_id"] for c in cves if c["cve_id"].startswith("CVE-")}
    print(f"\n[*] {len(unique_cves)} unique CVE IDs extracted.")
    print(f"[*] Run EPSS enrichment: python run.py enrich {output_path}")


if __name__ == "__main__":
    main()
