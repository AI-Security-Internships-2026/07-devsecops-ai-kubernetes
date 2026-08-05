"""
MCP server: report — run triage and read generated reports.

Run: python3 -m src.mcp_servers.report_mcp
"""

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from src import config
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


@mcp.tool()
def list_reports() -> list:
    """List saved triage reports (triage_run*.json) with image, timestamp, summary.

    Use this to see which images have already been triaged before answering (or
    before scanning again).
    """
    out = []
    for p in sorted(config.RESULTS_DIR.glob("triage_run*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append({
            "file": p.name,
            "image": data.get("container_image"),
            "timestamp": data.get("execution_timestamp"),
            "summary": data.get("summary", {}),
        })
    return out


@mcp.tool()
def get_report(image_or_path: str = "latest") -> dict:
    """Read a saved triage report by image name, file path, or 'latest'.

    Returns the image, summary counts, and the actionable (CRITICAL/HIGH) findings
    with their SSVC decision and rationale. Prefer this over re-scanning when the
    user asks about an image or report that has already been triaged.
    """
    reports = sorted(config.RESULTS_DIR.glob("triage_run*.json"),
                     key=lambda p: p.stat().st_mtime)
    if not reports:
        return {"found": False, "reason": "no triage_run*.json in the results dir"}

    target = None
    if not image_or_path or image_or_path == "latest":
        target = reports[-1]
    else:
        cand = Path(image_or_path)
        if cand.exists():
            target = cand
        else:
            safe = image_or_path.replace("/", "_").replace(":", "_")
            for p in reports:
                try:
                    img = json.loads(p.read_text(encoding="utf-8")).get("container_image") or ""
                except Exception:
                    img = ""
                if image_or_path in p.name or safe in p.name or image_or_path in img:
                    target = p
                    break
    if target is None:
        return {"found": False, "reason": f"no report matching '{image_or_path}'"}

    data = json.loads(target.read_text(encoding="utf-8"))
    actionable = [
        {
            "cve": f.get("cve_id"),
            "priority": f.get("priority"),
            "ssvc_decision": f.get("ssvc_decision"),
            "epss_score": f.get("epss_score"),
            "kev": f.get("kev_status"),
            "rationale": f.get("decision_rationale", ""),
        }
        for f in data.get("findings", [])
        if (f.get("priority") or "").upper() in ("CRITICAL", "HIGH")
    ]
    return {
        "found": True,
        "file": target.name,
        "image": data.get("container_image"),
        "timestamp": data.get("execution_timestamp"),
        "summary": data.get("summary", {}),
        "actionable_findings": actionable[:50],
    }


if __name__ == "__main__":
    mcp.run()
