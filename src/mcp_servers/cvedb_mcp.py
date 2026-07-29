"""
MCP server: cvedb — query the CVE intelligence database.

Run: python3 -m src.mcp_servers.cvedb_mcp
"""

from mcp.server.fastmcp import FastMCP

from src.database import db
from src.database.matcher import match_sbom_to_affected
from src.mcp_servers.common import to_jsonable

mcp = FastMCP("cvedb")


@mcp.tool()
def latest_cves(hours: int = 24) -> list:
    """CVEs ingested into our database within the last `hours`."""
    db.init_db()
    with db.get_conn() as conn:
        return [to_jsonable(dict(r)) for r in db.latest_cves(conn, hours)]


@mcp.tool()
def search_cve(cve_id: str) -> dict:
    """Look up a CVE in our database, including its affected package ranges."""
    db.init_db()
    with db.get_conn() as conn:
        row = db.get_cve(conn, cve_id)
        if not row:
            return {"found": False, "cve_id": cve_id}
        result = dict(row)
        result["found"] = True
        result["affected"] = [dict(a) for a in db.get_affected_packages(conn, cve_id)]
        return to_jsonable(result)


@mcp.tool()
def affected_images(cve_id: str) -> dict:
    """Which of OUR scanned images (by stored SBOM) are affected by this CVE?"""
    db.init_db()
    with db.get_conn() as conn:
        sbom_pkgs = [dict(r) for r in db.all_sbom_packages(conn)]
        affected = [dict(r) for r in db.matchable_affected(conn) if r["cve_id"] == cve_id]
    matches = match_sbom_to_affected(sbom_pkgs, affected)
    return {"cve_id": cve_id, "affected_images": sorted({m["image"] for m in matches})}


@mcp.tool()
def fresh_alerts() -> list:
    """All CVE-watch alerts (early-warning SBOM x feed matches)."""
    db.init_db()
    with db.get_conn() as conn:
        return [to_jsonable(dict(r)) for r in db.get_alerts(conn)]


if __name__ == "__main__":
    mcp.run()
