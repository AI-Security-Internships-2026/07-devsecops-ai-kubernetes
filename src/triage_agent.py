"""
LangGraph Triage Agent
Auto-generates a triage report from EPSS-prioritized CVE data using
SSVC decision logic + LLM-powered explanations.

This implements Stage 3 of the pipeline:
    Trivy (scan) → EPSS (enrich) → THIS AGENT (triage) → Report (output)

Usage:
    python src/triage_agent.py <epss_enriched_json>
    python src/triage_agent.py experiments/results/epss_enriched_trivy_nginx_latest.json
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, TypedDict

import httpx
from dotenv import load_dotenv
from langgraph.graph import END, StateGraph
from langchain_core.messages import HumanMessage, SystemMessage

load_dotenv()

OUTPUT_DIR = Path("experiments/results")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------------------------------
# State definition — this flows through the graph
# ---------------------------------------------------------------------------

class TriageState(TypedDict):
    input_file: str
    cves: list[dict]
    kev_catalog: set
    triage_decisions: list[dict]
    report_markdown: str
    report_json: dict


# ---------------------------------------------------------------------------
# SSVC Decision Logic
# ---------------------------------------------------------------------------

def ssvc_decide(cve: dict, in_kev: bool) -> dict:
    """
    Apply CISA SSVC decision tree to a single CVE.

    Decision logic:
        Act    — EPSS >= 0.1 OR in CISA KEV
        Attend — EPSS >= 0.01 AND (CVSS >= 7.0 OR HIGH/CRITICAL severity)
        Track* — EPSS >= 0.01 (moderate risk, worth monitoring)
        Track  — everything else (safe to defer)
    """
    epss = cve.get("epss_score", 0.0)
    cvss = cve.get("cvss_score", 0.0)
    severity = cve.get("severity", "UNKNOWN").upper()

    if epss >= 0.1 or in_kev:
        decision = "Act"
        urgency = "immediate"
        reason = []
        if in_kev:
            reason.append("listed in CISA Known Exploited Vulnerabilities catalog")
        if epss >= 0.1:
            reason.append(f"EPSS {epss:.3f} — {epss*100:.1f}% exploitation probability in 30 days")
        reasoning = "; ".join(reason)

    elif epss >= 0.01 and (cvss >= 7.0 or severity in ("CRITICAL", "HIGH")):
        decision = "Attend"
        urgency = "this_sprint"
        reasoning = (
            f"EPSS {epss:.3f} with {severity} severity (CVSS {cvss:.1f}) — "
            f"moderate exploit probability combined with high impact"
        )

    elif epss >= 0.01:
        decision = "Track*"
        urgency = "next_quarter"
        reasoning = f"EPSS {epss:.3f} — notable exploit probability but lower impact (CVSS {cvss:.1f})"

    else:
        decision = "Track"
        urgency = "defer"
        reasoning = f"EPSS {epss:.4f} — very low exploitation probability, safe to defer"

    return {
        **cve,
        "ssvc_decision": decision,
        "urgency": urgency,
        "reasoning": reasoning,
        "in_kev": in_kev,
    }


# ---------------------------------------------------------------------------
# Graph Nodes
# ---------------------------------------------------------------------------

def load_cves(state: TriageState) -> dict:
    """Node 1: Load EPSS-enriched CVEs from JSON file."""
    input_path = Path(state["input_file"])
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        sys.exit(1)

    cves = json.loads(input_path.read_text())
    print(f"[+] Loaded {len(cves)} CVEs from {input_path.name}")

    # Filter to only those with EPSS data (already sorted by epss_score desc)
    actionable = [c for c in cves if c.get("epss_score", 0) > 0]
    print(f"[+] {len(actionable)} CVEs have EPSS scores > 0")

    return {"cves": actionable}


def fetch_kev_catalog(state: TriageState) -> dict:
    """Node 2: Fetch CISA Known Exploited Vulnerabilities catalog."""
    print("[*] Fetching CISA KEV catalog...")

    try:
        response = httpx.get(CISA_KEV_URL, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
        kev_ids = {v["cveID"] for v in data.get("vulnerabilities", [])}
        print(f"[+] KEV catalog loaded: {len(kev_ids)} known exploited CVEs")
    except Exception as e:
        print(f"[!] Could not fetch KEV catalog: {e}")
        print("[*] Continuing without KEV data (EPSS-only decisions)")
        kev_ids = set()

    return {"kev_catalog": kev_ids}


def apply_ssvc(state: TriageState) -> dict:
    """Node 3: Apply SSVC decision tree to all CVEs."""
    cves = state["cves"]
    kev_catalog = state["kev_catalog"]

    decisions = []
    for cve in cves:
        in_kev = cve["cve_id"] in kev_catalog
        decision = ssvc_decide(cve, in_kev)
        decisions.append(decision)

    # Count by decision
    counts = {}
    for d in decisions:
        dec = d["ssvc_decision"]
        counts[dec] = counts.get(dec, 0) + 1

    print(f"[+] SSVC decisions applied:")
    print(f"    Act:    {counts.get('Act', 0)} (fix immediately)")
    print(f"    Attend: {counts.get('Attend', 0)} (fix this sprint)")
    print(f"    Track*: {counts.get('Track*', 0)} (monitor)")
    print(f"    Track:  {counts.get('Track', 0)} (defer)")

    return {"triage_decisions": decisions}


def generate_report(state: TriageState) -> dict:
    """Node 4: Generate triage report using LLM for 'Act' items + structured output."""
    decisions = state["triage_decisions"]
    input_file = state["input_file"]

    act_items = [d for d in decisions if d["ssvc_decision"] == "Act"]
    attend_items = [d for d in decisions if d["ssvc_decision"] == "Attend"]
    track_star = [d for d in decisions if d["ssvc_decision"] == "Track*"]
    track_items = [d for d in decisions if d["ssvc_decision"] == "Track"]

    total = len(decisions)
    alert_reduction = (len(track_items) + len(track_star)) / max(total, 1) * 100

    # Try to use LLM for executive summary and fix recommendations
    llm_summary = _generate_llm_summary(act_items, attend_items, total, alert_reduction)

    # Build markdown report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = []
    md.append("# Vulnerability Triage Report")
    md.append(f"\n**Generated:** {now}")
    md.append(f"**Source:** `{Path(input_file).name}`")
    md.append(f"**Total CVEs analyzed:** {total}")
    md.append(f"**Alert reduction:** {alert_reduction:.1f}% (Track + Track*)")
    md.append("")

    md.append("## Executive Summary")
    md.append("")
    if llm_summary:
        md.append(llm_summary)
    else:
        md.append(
            f"Of {total} vulnerabilities scanned, **{len(act_items)} require immediate action** "
            f"and **{len(attend_items)} should be addressed this sprint**. "
            f"{alert_reduction:.0f}% of findings are safe to defer."
        )
    md.append("")

    md.append("## Decision Breakdown")
    md.append("")
    md.append("| Decision | Count | Action Required |")
    md.append("|----------|-------|-----------------|")
    md.append(f"| **Act** | {len(act_items)} | Fix immediately — block deployment |")
    md.append(f"| **Attend** | {len(attend_items)} | Fix this sprint |")
    md.append(f"| **Track*** | {len(track_star)} | Monitor — reassess next quarter |")
    md.append(f"| **Track** | {len(track_items)} | Safe to defer |")
    md.append("")

    # Act items detail
    if act_items:
        md.append("## Immediate Action Required (Act)")
        md.append("")
        md.append("| CVE | Package | EPSS | CVSS | KEV | Reason |")
        md.append("|-----|---------|------|------|-----|--------|")
        for item in act_items:
            kev_flag = "Yes" if item.get("in_kev") else "No"
            md.append(
                f"| {item['cve_id']} | {item.get('package', 'N/A')} | "
                f"{item['epss_score']:.3f} | {item.get('cvss_score', 0):.1f} | "
                f"{kev_flag} | {item['reasoning'][:80]} |"
            )
        md.append("")

    # Attend items detail
    if attend_items:
        md.append("## Fix This Sprint (Attend)")
        md.append("")
        md.append("| CVE | Package | EPSS | CVSS | Severity |")
        md.append("|-----|---------|------|------|----------|")
        for item in attend_items[:20]:
            md.append(
                f"| {item['cve_id']} | {item.get('package', 'N/A')} | "
                f"{item['epss_score']:.3f} | {item.get('cvss_score', 0):.1f} | "
                f"{item.get('severity', 'N/A')} |"
            )
        if len(attend_items) > 20:
            md.append(f"\n*...and {len(attend_items) - 20} more Attend items.*")
        md.append("")

    # Methodology note
    md.append("## Methodology")
    md.append("")
    md.append("This report uses the **CISA SSVC** (Stakeholder-Specific Vulnerability Categorization) framework:")
    md.append("- **EPSS** (Exploit Prediction Scoring System) for exploitation probability")
    md.append("- **CISA KEV** catalog for confirmed actively-exploited vulnerabilities")
    md.append("- **CVSS** base score for impact assessment")
    md.append("")
    md.append("Decision thresholds:")
    md.append("- **Act**: EPSS >= 0.1 (10%+ exploit probability) OR in CISA KEV")
    md.append("- **Attend**: EPSS >= 0.01 AND (CVSS >= 7.0 OR severity CRITICAL/HIGH)")
    md.append("- **Track***: EPSS >= 0.01 (moderate probability, lower impact)")
    md.append("- **Track**: EPSS < 0.01 (very low exploitation probability)")

    report_markdown = "\n".join(md)

    # Build JSON report
    report_json = {
        "generated_at": now,
        "source_file": str(Path(input_file).name),
        "summary": {
            "total_cves": total,
            "act": len(act_items),
            "attend": len(attend_items),
            "track_star": len(track_star),
            "track": len(track_items),
            "alert_reduction_pct": round(alert_reduction, 1),
        },
        "decisions": decisions,
    }

    return {"report_markdown": report_markdown, "report_json": report_json}


def _generate_llm_summary(
    act_items: list[dict],
    attend_items: list[dict],
    total: int,
    alert_reduction: float,
) -> str | None:
    """Use LLM to generate an executive summary. Returns None if no API key."""
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("[*] No GOOGLE_API_KEY found — generating report without LLM summary")
        return None

    model_name = os.getenv("LLM_MODEL", "gemini-2.5-pro-preview-05-06")
    print(f"[*] Generating LLM executive summary using {model_name}...")

    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(model=model_name, temperature=0.2, google_api_key=api_key)

        act_summary = "\n".join(
            f"- {item['cve_id']}: {item.get('title', 'N/A')} (EPSS: {item['epss_score']:.3f}, "
            f"package: {item.get('package', 'unknown')})"
            for item in act_items[:10]
        )

        prompt = f"""You are a Kubernetes security analyst. Generate a concise executive summary
(3-5 sentences) for a vulnerability triage report.

Key facts:
- {total} total CVEs analyzed
- {len(act_items)} require immediate action (SSVC: Act)
- {len(attend_items)} should be fixed this sprint (SSVC: Attend)
- {alert_reduction:.0f}% of findings are safe to defer
- The scan target is a container image in a Kubernetes cluster

Top "Act" findings:
{act_summary if act_items else "None — no immediate action required."}

Write a professional, actionable summary. Focus on risk, not just counts.
Do NOT use markdown headers. Start directly with the assessment."""

        response = llm.invoke([
            SystemMessage(content="You are a concise security report writer."),
            HumanMessage(content=prompt),
        ])

        summary = response.content.strip()
        print(f"[+] LLM summary generated ({len(summary)} chars)")
        return summary

    except Exception as e:
        print(f"[!] LLM call failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Build and run the graph
# ---------------------------------------------------------------------------

def build_triage_graph() -> StateGraph:
    """Construct the LangGraph triage workflow."""
    graph = StateGraph(TriageState)

    graph.add_node("load_cves", load_cves)
    graph.add_node("fetch_kev", fetch_kev_catalog)
    graph.add_node("apply_ssvc", apply_ssvc)
    graph.add_node("generate_report", generate_report)

    graph.set_entry_point("load_cves")
    graph.add_edge("load_cves", "fetch_kev")
    graph.add_edge("fetch_kev", "apply_ssvc")
    graph.add_edge("apply_ssvc", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def run_triage(input_file: str) -> tuple[str, dict]:
    """
    Run the full triage pipeline on an EPSS-enriched JSON file.

    Returns:
        (markdown_report, json_report)
    """
    graph = build_triage_graph()
    app = graph.compile()

    print(f"\n{'='*70}")
    print("LANGGRAPH TRIAGE AGENT — SSVC Vulnerability Prioritization")
    print(f"{'='*70}\n")

    initial_state = {
        "input_file": input_file,
        "cves": [],
        "kev_catalog": set(),
        "triage_decisions": [],
        "report_markdown": "",
        "report_json": {},
    }

    final_state = app.invoke(initial_state)

    return final_state["report_markdown"], final_state["report_json"]


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/triage_agent.py <epss_enriched_json>")
        print("Example: python src/triage_agent.py experiments/results/epss_enriched_trivy_nginx_latest.json")
        sys.exit(1)

    input_file = sys.argv[1]

    # Run the triage agent
    report_md, report_json = run_triage(input_file)

    # Save outputs
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    input_name = Path(input_file).stem.replace("epss_enriched_", "")

    md_path = OUTPUT_DIR / f"triage_report_{input_name}.md"
    md_path.write_text(report_md)
    print(f"\n[+] Markdown report saved: {md_path}")

    json_path = OUTPUT_DIR / f"triage_report_{input_name}.json"
    json_path.write_text(json.dumps(report_json, indent=2, default=str))
    print(f"[+] JSON report saved: {json_path}")

    # Print summary to terminal
    summary = report_json.get("summary", {})
    print(f"\n{'='*70}")
    print("TRIAGE COMPLETE")
    print(f"{'='*70}")
    print(f"  Total CVEs:      {summary.get('total_cves', 0)}")
    print(f"  Act (immediate): {summary.get('act', 0)}")
    print(f"  Attend (sprint): {summary.get('attend', 0)}")
    print(f"  Track* (monitor):{summary.get('track_star', 0)}")
    print(f"  Track (defer):   {summary.get('track', 0)}")
    print(f"  Alert reduction: {summary.get('alert_reduction_pct', 0)}%")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
