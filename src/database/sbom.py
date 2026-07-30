"""
SBOM generation + storage.

Generates a CycloneDX SBOM for an image via Trivy, extracts its packages
(name, version, purl, ecosystem), and stores them in the CVE intelligence DB.

Usage:
    python run.py sbom <image>
"""

import json
import subprocess
import sys

from src import config
from src.database import db


def ecosystem_from_purl(purl: str) -> str:
    """Extract the ecosystem/type from a purl, e.g. 'pkg:golang/...' -> 'golang'."""
    if not purl or not purl.startswith("pkg:"):
        return ""
    rest = purl[len("pkg:"):]
    return rest.split("/", 1)[0].split("@", 1)[0]


def parse_sbom(cyclonedx: dict) -> list[dict]:
    """Extract package records from a CycloneDX document."""
    packages = []
    for comp in cyclonedx.get("components", []):
        name = comp.get("name")
        if not name:
            continue
        purl = comp.get("purl", "")
        packages.append({
            "package_name": name,
            "version": comp.get("version", ""),
            "purl": purl,
            "ecosystem": ecosystem_from_purl(purl) or comp.get("type", ""),
        })
    return packages


def generate_sbom(image: str) -> dict:
    """Run Trivy to produce a CycloneDX SBOM for an image. Returns the parsed JSON."""
    cmd = ["trivy", "image", "--format", "cyclonedx", "--quiet", image]
    print(f"[*] Generating SBOM: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("[!] Trivy not installed or not in PATH.")
        raise
    except subprocess.TimeoutExpired:
        print("[!] Trivy SBOM generation timed out.")
        raise
    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(f"Trivy SBOM failed: {result.stderr[:300]}")
    return json.loads(result.stdout)


def generate_and_store(image: str) -> tuple[str, int]:
    """Generate an SBOM, save the file, and store its packages in the DB.

    Returns (sbom_path, package_count).
    """
    config.ensure_dirs()
    db.init_db()

    cyclonedx = generate_sbom(image)
    packages = parse_sbom(cyclonedx)

    safe = image.replace("/", "_").replace(":", "_")
    sbom_path = config.SBOM_DIR / f"{safe}.cdx.json"
    sbom_path.write_text(json.dumps(cyclonedx, indent=2), encoding="utf-8")

    with db.get_conn() as conn:
        sbom_id = db.insert_sbom(conn, image, str(sbom_path))
        for pkg in packages:
            db.add_sbom_package(conn, sbom_id, pkg)
        conn.commit()

    print(f"[+] SBOM stored: {len(packages)} packages from {image} -> {sbom_path}")
    return str(sbom_path), len(packages)


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.database.sbom <image>")
        sys.exit(1)
    generate_and_store(sys.argv[1])


if __name__ == "__main__":
    main()
