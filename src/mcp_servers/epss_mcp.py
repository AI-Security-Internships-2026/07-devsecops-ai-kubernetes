"""
MCP server: epss — Exploit Prediction Scoring System lookups.

Run: python3 -m src.mcp_servers.epss_mcp
"""

from mcp.server.fastmcp import FastMCP

from src.enrichment.epss_client import fetch_epss_scores

mcp = FastMCP("epss")


@mcp.tool()
def get_epss(cve_id: str) -> dict:
    """Get the EPSS score (exploit probability, 0-1) and percentile for one CVE."""
    scores = fetch_epss_scores([cve_id])
    return scores.get(cve_id, {"epss": 0.0, "percentile": 0.0})


@mcp.tool()
def batch_epss(cve_ids: list[str]) -> dict:
    """Get EPSS scores for many CVEs at once. Returns {cve_id: {epss, percentile}}."""
    return fetch_epss_scores(cve_ids)


if __name__ == "__main__":
    mcp.run()
