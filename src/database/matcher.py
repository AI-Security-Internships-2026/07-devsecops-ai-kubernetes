"""
SBOM x feed matcher.

Compares affected-package version ranges (from NVD/OSV, stored in the DB)
against the package versions in our stored SBOMs, to find which of OUR images
are hit by a CVE. This is what lets us alert on a freshly-published CVE hours
before the scanner's own database catches up.

CAVEAT (documented, not hidden): Debian/RHEL backport patched versions without
bumping the upstream version, so naive version comparison can produce false
positives. Matches are therefore flagged `needs_verification=True` and our
layer is positioned as EARLY WARNING, with Trivy as the confirmatory scan.

Version comparison + matching are pure.
"""

import re

from src.database import db


def _version_key(v: str) -> list[int]:
    """Loose numeric version key: extract integer components for comparison.

    '0.23.0' -> [0,23,0];  '2.31-13+deb11u5' -> [2,31,13,11,5]
    Good enough for semver-ish comparisons; imperfect for distro epochs (hence
    the needs_verification flag on matches).
    """
    if not v:
        return [0]
    nums = re.findall(r"\d+", v)
    return [int(n) for n in nums] or [0]


def version_lt(a: str, b: str) -> bool:
    """True if version a < version b under the loose numeric key."""
    return _version_key(a) < _version_key(b)


def version_gte(a: str, b: str) -> bool:
    return _version_key(a) >= _version_key(b)


def is_affected(installed: str, introduced: str | None, fixed: str | None) -> bool:
    """
    Is `installed` within the vulnerable range [introduced, fixed)?

    - fixed known: affected if installed < fixed (and >= introduced if given)
    - fixed unknown, introduced given: affected if installed >= introduced
    - neither: cannot tell -> treat as affected (conservative; verification flag set)
    """
    if fixed and fixed not in ("0", ""):
        if version_lt(installed, fixed):
            if introduced and introduced not in ("0", ""):
                return version_gte(installed, introduced)
            return True
        return False
    if introduced and introduced not in ("0", ""):
        return version_gte(installed, introduced)
    return True


def match_sbom_to_affected(sbom_pkgs: list[dict], affected: list[dict]) -> list[dict]:
    """
    Pure matching core. Returns a list of match records:
        {cve_id, image, package_name, installed_version, version_fixed,
         ecosystem, in_kev, epss_score, cvss_score, severity, source}
    """
    # index affected rows by lowercased package name
    by_name: dict[str, list[dict]] = {}
    for a in affected:
        by_name.setdefault(a["package_name"].lower(), []).append(a)

    matches = []
    for pkg in sbom_pkgs:
        name = (pkg.get("package_name") or "").lower()
        installed = pkg.get("version") or ""
        for a in by_name.get(name, []):
            if is_affected(installed, a.get("version_introduced"), a.get("version_fixed")):
                matches.append({
                    "cve_id": a["cve_id"],
                    "image": pkg["image"],
                    "package_name": pkg["package_name"],
                    "installed_version": installed,
                    "version_fixed": a.get("version_fixed"),
                    "ecosystem": a.get("ecosystem"),
                    "in_kev": bool(a.get("in_kev")),
                    "epss_score": a.get("epss_score"),
                    "cvss_score": a.get("cvss_score"),
                    "severity": a.get("severity"),
                    "source": a.get("source"),
                })
    return matches


def find_matches(conn) -> list[dict]:
    """Load SBOM packages + affected ranges from the DB and match them."""
    sbom_rows = db.all_sbom_packages(conn)
    affected_rows = db.matchable_affected(conn)
    sbom_pkgs = [dict(r) for r in sbom_rows]
    affected = [dict(r) for r in affected_rows]
    return match_sbom_to_affected(sbom_pkgs, affected)
