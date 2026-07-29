"""
MCP server: scanner — Trivy scanning + SBOM generation.

Run: python3 -m src.mcp_servers.scanner_mcp
"""

from mcp.server.fastmcp import FastMCP

from src.scanners.trivy_scanner import run_trivy_scan, extract_cves
from src.database.sbom import generate_and_store

mcp = FastMCP("scanner")


@mcp.tool()
def scan_image(image: str) -> dict:
    """Run a Trivy vulnerability scan on a container image.

    Returns the output JSON path, total CVE count, and the list of CVE IDs
    (capped at 500). Use this to discover what vulnerabilities an image contains.
    """
    results, path = run_trivy_scan(image)
    cves = extract_cves(results)
    return {
        "image": image,
        "output_path": str(path),
        "cve_count": len(cves),
        "cve_ids": sorted({c["cve_id"] for c in cves if c["cve_id"].startswith("CVE-")})[:500],
    }


@mcp.tool()
def get_sbom(image: str) -> dict:
    """Generate a CycloneDX SBOM for an image and store it in the intelligence DB.

    Returns the SBOM file path and the number of packages found. The stored SBOM
    is what the CVE watcher matches freshly-published CVEs against.
    """
    path, count = generate_and_store(image)
    return {"image": image, "sbom_path": path, "package_count": count}


if __name__ == "__main__":
    mcp.run()
