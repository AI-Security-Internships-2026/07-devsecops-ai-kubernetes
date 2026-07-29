"""
MCP server: kev — CISA Known Exploited Vulnerabilities lookups.

Run: python3 -m src.mcp_servers.kev_mcp
"""

from mcp.server.fastmcp import FastMCP

from src.mcp_servers.common import kev_ids

mcp = FastMCP("kev")


@mcp.tool()
def check_kev(cve_id: str) -> dict:
    """Is this CVE in CISA's Known Exploited Vulnerabilities catalog (confirmed exploited)?"""
    return {"cve_id": cve_id, "in_kev": cve_id.upper() in kev_ids()}


@mcp.tool()
def kev_count() -> int:
    """Total number of CVEs currently in the CISA KEV catalog."""
    return len(kev_ids())


if __name__ == "__main__":
    mcp.run()
