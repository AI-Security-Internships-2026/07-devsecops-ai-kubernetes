"""
MCP server: report — run triage and read generated reports.

Run: python3 -m src.mcp_servers.report_mcp
"""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from src.triage.triage_agent import run_triage, save_reports

mcp = FastMCP("report")


@mcp.tool()
def triage(epss_json_path: str) -> dict:
    """Run SSVC + LLM triage on an EPSS-enriched JSON file.

    Returns the decision summary and the paths of the generated markdown/JSON
    reports.
    """
    report_md, report_json = run_triage(epss_json_path)
    md_path, json_path = save_reports(report_md, report_json, epss_json_path)
    return {
        "summary": report_json.get("summary", {}),
        "markdown_path": str(md_path),
        "json_path": str(json_path),
    }


@mcp.tool()
def read_report(path: str) -> str:
    """Return the contents of a previously generated report file."""
    p = Path(path)
    if not p.exists():
        return f"[not found] {path}"
    return p.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run()
