"""
MCP server: ssvc — CISA SSVC decision engine.

Run: python3 -m src.mcp_servers.ssvc_mcp
"""

from mcp.server.fastmcp import FastMCP

from src.triage import ssvc

mcp = FastMCP("ssvc")


@mcp.tool()
def classify_cve(
    cve_id: str,
    epss_score: float = 0.0,
    cvss_score: float = 0.0,
    severity: str = "UNKNOWN",
    in_kev: bool = False,
    exposed: bool = False,
    privileged: bool = False,
    exploit_exists: bool = False,
) -> dict:
    """Classify a CVE into an SSVC decision (Act/Attend/Track*/Track).

    Optionally supply Kubernetes context (exposed/privileged) and whether a
    public exploit exists; these refine the base EPSS/CVSS/KEV decision. Returns
    {priority, decision, notes}.
    """
    cve = {
        "cve_id": cve_id, "epss_score": epss_score, "cvss_score": cvss_score,
        "severity": severity, "in_kev": in_kev,
    }
    context = None
    if exposed or privileged:
        context = {"available": True, "deployed": True, "exposed": exposed,
                   "exposure_type": "LoadBalancer" if exposed else None,
                   "privileged": privileged}
    return ssvc.analyze(cve, in_kev, context=context, exploit_exists=exploit_exists)


@mcp.tool()
def get_thresholds() -> dict:
    """Return the SSVC decision thresholds this engine uses."""
    return {
        "CRITICAL/Act": "EPSS >= 0.1 OR in CISA KEV",
        "HIGH/Attend": "EPSS >= 0.01 AND (CVSS >= 7.0 OR severity CRITICAL/HIGH)",
        "MEDIUM/Track*": "EPSS >= 0.01",
        "LOW/Track": "EPSS < 0.01",
        "refinements": "public exploit or internet exposure escalates; "
                       "internal-only borderline criticals de-escalate",
    }


if __name__ == "__main__":
    mcp.run()
