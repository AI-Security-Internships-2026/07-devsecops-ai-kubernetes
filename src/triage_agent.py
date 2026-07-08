"""
LangGraph Triage Agent
Auto-generates a triage report from EPSS-prioritized CVE data using
SSVC decision logic + LLM-powered per-CVE explanations.

This implements Stage 3 of the pipeline:
    Trivy (scan) → EPSS (enrich) → THIS AGENT (triage) → Report (output)

Architecture (ref: AgenticVM 2026):
    StateGraph with 3 nodes:
        ingest_node   — reads EPSS-prioritized CVE JSON
        analysis_node — SSVC classification + LLM risk explanation per CVE
        report_node   — outputs structured triage report (Markdown + JSON)

Usage:
    python src/triage_agent.py <epss_enriched_json>
    python src/triage_agent.py experiments/results/epss_enriched_trivy_nginx_latest.json
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

import httpx
from dotenv import load_dotenv
from langgraph.graph import END, StateGraph
from langchain_core.messages import HumanMessage, SystemMessage

load_dotenv()

OUTPUT_DIR = Path("experiments/results")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------------------------------
# State definition — flows through the graph
# ---------------------------------------------------------------------------

class TriageState(TypedDict):
    input_file: str
    raw_cves: list[dict]
    kev_catalog: set
    analyzed_cves: list[dict]
    report_markdown: str
    report_json: dict


# ---------------------------------------------------------------------------
# LLM setup — supports Groq (Llama-3.1) and Google Gemini as fallback
# ---------------------------------------------------------------------------

def _get_llm():
    """Get configured LLM. Tries Groq first, then Gemini, returns None if neither."""
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        model = os.getenv("LLM_MODEL", "llama-3.1-8b-instant")
        print(f"[*] Using Groq ({model})")
        from langchain_groq import ChatGroq
        return ChatGroq(model=model, temperature=0.2, api_key=groq_key)

    google_key = os.getenv("GOOGLE_API_KEY")
    if google_key:
        model = os.getenv("LLM_MODEL", "gemini-2.5-pro-preview-05-06")
        print(f"[*] Using Google Gemini ({model})")
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model=model, temperature=0.2, google_api_key=google_key)

    return None


def _llm_analyze_cve(llm, cve: dict, in_kev: bool) -> dict:
    """Call LLM to generate plain-English explanation + recommended action for one CVE."""
    kev_note = " This CVE is listed in CISA's Known Exploited Vulnerabilities catalog — confirmed active exploitation." if in_kev else ""

    prompt = f"""You are a Kubernetes security analyst. Analyze this vulnerability and provide:
1. A plain-English risk explanation (2-3 sentences)
2. A recommended action (1 sentence)

Vulnerability details:
- CVE: {cve['cve_id']}
- Title: {cve.get('title', 'N/A')}
- Package: {cve.get('package', 'unknown')} (installed: {cve.get('installed_version', '?')}, fixed: {cve.get('fixed_version', 'N/A')})
- EPSS Score: {cve.get('epss_score', 0):.3f} ({cve.get('epss_score', 0)*100:.1f}% exploit probability in 30 days)
- CVSS: {cve.get('cvss_score', 0):.1f}
- Severity: {cve.get('severity', 'UNKNOWN')}
- CISA KEV: {'YES — actively exploited' if in_kev else 'No'}{kev_note}

Respond ONLY in this exact JSON format, no markdown fences:
{{"explanation": "your 2-3 sentence explanation here", "recommended_action": "your 1 sentence action here"}}"""

    try:
        response = llm.invoke([
            SystemMessage(content="You are a concise security analyst. Always respond in valid JSON only."),
            HumanMessage(content=prompt),
        ])
        text = response.content.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        return json.loads(text)
    except Exception:
        return None


def _static_explanation(cve: dict, priority: str, in_kev: bool) -> dict:
    """Generate a deterministic explanation when no LLM is available."""
    epss = cve.get("epss_score", 0)
    pkg = cve.get("package", "unknown")
    fixed = cve.get("fixed_version", "")
    title = cve.get("title", "N/A")

    if priority == "CRITICAL":
        expl = (
            f"This vulnerability ({title}) in {pkg} has a {epss*100:.1f}% probability of "
            f"exploitation in the next 30 days."
        )
        if in_kev:
            expl += " Active exploitation confirmed in CISA KEV."
        action = f"Patch within 24h{' — upgrade to ' + fixed if fixed else ' or isolate container'}."
    elif priority == "HIGH":
        expl = (
            f"{title} in {pkg} has notable exploit risk (EPSS {epss:.3f}). "
            f"Combined with its severity, this warrants prompt attention."
        )
        action = f"Schedule fix this sprint{' — upgrade to ' + fixed if fixed else ''}."
    elif priority == "MEDIUM":
        expl = (
            f"{title} in {pkg} has moderate exploit probability (EPSS {epss:.3f}). "
            f"Lower impact reduces urgency but the vulnerability should be tracked."
        )
        action = "Monitor and reassess next quarter."
    else:
        expl = (
            f"{title} in {pkg} has very low exploit probability (EPSS {epss:.4f}). "
            f"Safe to defer."
        )
        action = "No immediate action required. Track for changes."

    return {"explanation": expl, "recommended_action": action}


# ---------------------------------------------------------------------------
# SSVC Decision Logic
# ---------------------------------------------------------------------------

def _classify_priority(cve: dict, in_kev: bool) -> tuple[str, str]:
    """
    Apply CISA SSVC decision tree. Returns (priority, ssvc_decision).

    Decision logic:
        CRITICAL / Act    — EPSS >= 0.1 OR in CISA KEV
        HIGH / Attend     — EPSS >= 0.01 AND (CVSS >= 7.0 OR CRITICAL/HIGH severity)
        MEDIUM / Track*   — EPSS >= 0.01
        LOW / Track       — everything else
    """
    epss = cve.get("epss_score", 0.0)
    cvss = cve.get("cvss_score", 0.0)
    severity = cve.get("severity", "UNKNOWN").upper()

    if epss >= 0.1 or in_kev:
        return "CRITICAL", "Act"
    elif epss >= 0.01 and (cvss >= 7.0 or severity in ("CRITICAL", "HIGH")):
        return "HIGH", "Attend"
    elif epss >= 0.01:
        return "MEDIUM", "Track*"
    else:
        return "LOW", "Track"


# ---------------------------------------------------------------------------
# Node 1: ingest_node
# ---------------------------------------------------------------------------

def ingest_node(state: TriageState) -> dict:
    """Read EPSS-prioritized CVE JSON and fetch CISA KEV catalog."""
    input_path = Path(state["input_file"])
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        sys.exit(1)

    cves = json.loads(input_path.read_text())
    print(f"[+] Ingested {len(cves)} CVEs from {input_path.name}")

    actionable = [c for c in cves if c.get("epss_score", 0) > 0]
    print(f"[+] {len(actionable)} CVEs have EPSS scores > 0")

    # Fetch CISA KEV catalog
    print("[*] Fetching CISA KEV catalog...")
    kev_ids = set()
    try:
        response = httpx.get(CISA_KEV_URL, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
        kev_ids = {v["cveID"] for v in data.get("vulnerabilities", [])}
        print(f"[+] KEV catalog: {len(kev_ids)} known exploited CVEs")
    except Exception as e:
        print(f"[!] Could not fetch KEV catalog: {e}")
        print("[*] Continuing without KEV data")

    return {"raw_cves": actionable, "kev_catalog": kev_ids}


# ---------------------------------------------------------------------------
# Node 2: analysis_node
# ---------------------------------------------------------------------------

def analysis_node(state: TriageState) -> dict:
    """Classify each CVE with SSVC + generate LLM explanation per CVE."""
    cves = state["raw_cves"]
    kev_catalog = state["kev_catalog"]

    llm = _get_llm()
    if not llm:
        print("[*] No LLM API key found — using static explanations")
        print("[*] Set GROQ_API_KEY (free: console.groq.com) or GOOGLE_API_KEY for LLM analysis")

    analyzed = []
    act_count = attend_count = track_star_count = track_count = 0

    for i, cve in enumerate(cves):
        in_kev = cve["cve_id"] in kev_catalog
        priority, ssvc_decision = _classify_priority(cve, in_kev)

        # LLM explanation for CRITICAL and HIGH priority CVEs
        llm_result = None
        if llm and priority in ("CRITICAL", "HIGH"):
            llm_result = _llm_analyze_cve(llm, cve, in_kev)
            if llm_result:
                print(f"    [{i+1}/{len(cves)}] {cve['cve_id']} → {priority} (LLM)")

        if not llm_result:
            llm_result = _static_explanation(cve, priority, in_kev)

        analyzed.append({
            "cve": cve["cve_id"],
            "epss_score": cve.get("epss_score", 0.0),
            "cvss_score": cve.get("cvss_score", 0.0),
            "severity": cve.get("severity", "UNKNOWN"),
            "package": cve.get("package", "unknown"),
            "installed_version": cve.get("installed_version", ""),
            "fixed_version": cve.get("fixed_version", ""),
            "title": cve.get("title", ""),
            "priority": priority,
            "ssvc_decision": ssvc_decision,
            "in_kev": in_kev,
            "explanation": llm_result["explanation"],
            "recommended_action": llm_result["recommended_action"],
        })

        if ssvc_decision == "Act":
            act_count += 1
        elif ssvc_decision == "Attend":
            attend_count += 1
        elif ssvc_decision == "Track*":
            track_star_count += 1
        else:
            track_count += 1

    print(f"\n[+] Analysis complete:")
    print(f"    CRITICAL / Act:    {act_count}")
    print(f"    HIGH / Attend:     {attend_count}")
    print(f"    MEDIUM / Track*:   {track_star_count}")
    print(f"    LOW / Track:       {track_count}")

    return {"analyzed_cves": analyzed}


# ---------------------------------------------------------------------------
# Node 3: report_node
# ---------------------------------------------------------------------------

def report_node(state: TriageState) -> dict:
    """Generate structured triage report in Markdown and JSON."""
    analyzed = state["analyzed_cves"]
    input_file = state["input_file"]

    act_items = [c for c in analyzed if c["priority"] == "CRITICAL"]
    attend_items = [c for c in analyzed if c["priority"] == "HIGH"]
    track_star = [c for c in analyzed if c["priority"] == "MEDIUM"]
    track_items = [c for c in analyzed if c["priority"] == "LOW"]

    total = len(analyzed)
    alert_reduction = (len(track_items) + len(track_star)) / max(total, 1) * 100

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- Markdown report ---
    md = []
    md.append("# Vulnerability Triage Report")
    md.append(f"\n**Generated:** {now}")
    md.append(f"**Source:** `{Path(input_file).name}`")
    md.append(f"**Total CVEs analyzed:** {total}")
    md.append(f"**Alert reduction:** {alert_reduction:.1f}%")
    md.append("")

    md.append("## Executive Summary")
    md.append("")
    md.append(
        f"Of {total} vulnerabilities analyzed, **{len(act_items)} require immediate action** "
        f"(CRITICAL) and **{len(attend_items)} should be addressed this sprint** (HIGH). "
        f"{alert_reduction:.0f}% of findings are safe to defer, reducing alert fatigue "
        f"from {total} raw CVEs to {len(act_items) + len(attend_items)} actionable items."
    )
    md.append("")

    md.append("## Decision Breakdown")
    md.append("")
    md.append("| Priority | SSVC Decision | Count | Action Required |")
    md.append("|----------|---------------|-------|-----------------|")
    md.append(f"| CRITICAL | Act | {len(act_items)} | Fix immediately — block deployment |")
    md.append(f"| HIGH | Attend | {len(attend_items)} | Fix this sprint |")
    md.append(f"| MEDIUM | Track* | {len(track_star)} | Monitor — reassess next quarter |")
    md.append(f"| LOW | Track | {len(track_items)} | Safe to defer |")
    md.append("")

    # Detailed findings for Act + Attend
    if act_items:
        md.append("## CRITICAL — Immediate Action Required")
        md.append("")
        for item in act_items:
            kev = " | **CISA KEV: YES**" if item["in_kev"] else ""
            fixed = f" → upgrade to `{item['fixed_version']}`" if item["fixed_version"] else ""
            md.append(f"### {item['cve']}")
            md.append(f"**Package:** `{item['package']}` (`{item['installed_version']}`){fixed}  ")
            md.append(f"**EPSS:** {item['epss_score']:.3f} | **CVSS:** {item['cvss_score']:.1f}{kev}  ")
            md.append(f"**Explanation:** {item['explanation']}  ")
            md.append(f"**Action:** {item['recommended_action']}")
            md.append("")

    if attend_items:
        md.append("## HIGH — Fix This Sprint")
        md.append("")
        for item in attend_items[:15]:
            fixed = f" → `{item['fixed_version']}`" if item["fixed_version"] else ""
            md.append(f"### {item['cve']}")
            md.append(f"**Package:** `{item['package']}` (`{item['installed_version']}`){fixed}  ")
            md.append(f"**EPSS:** {item['epss_score']:.3f} | **CVSS:** {item['cvss_score']:.1f}  ")
            md.append(f"**Explanation:** {item['explanation']}  ")
            md.append(f"**Action:** {item['recommended_action']}")
            md.append("")
        if len(attend_items) > 15:
            md.append(f"*...and {len(attend_items) - 15} more HIGH priority items.*\n")

    md.append("## Methodology")
    md.append("")
    md.append("This report uses **CISA SSVC** with **EPSS** exploit probability scoring:")
    md.append("- **CRITICAL/Act**: EPSS >= 0.1 (10%+ exploitation probability) OR in CISA KEV")
    md.append("- **HIGH/Attend**: EPSS >= 0.01 AND (CVSS >= 7.0 OR CRITICAL/HIGH severity)")
    md.append("- **MEDIUM/Track***: EPSS >= 0.01 (moderate probability, lower impact)")
    md.append("- **LOW/Track**: EPSS < 0.01 (very low exploitation probability)")
    md.append("")
    md.append("*Reference: AgenticVM (Arifin et al., 2026) — multi-agent vulnerability management architecture.*")

    report_markdown = "\n".join(md)

    # --- JSON report ---
    report_json = {
        "generated_at": now,
        "source_file": str(Path(input_file).name),
        "summary": {
            "total_cves": total,
            "critical_act": len(act_items),
            "high_attend": len(attend_items),
            "medium_track_star": len(track_star),
            "low_track": len(track_items),
            "alert_reduction_pct": round(alert_reduction, 1),
        },
        "findings": analyzed,
    }

    return {"report_markdown": report_markdown, "report_json": report_json}


# ---------------------------------------------------------------------------
# Build and run the graph
# ---------------------------------------------------------------------------

def build_triage_graph() -> StateGraph:
    """Construct the LangGraph triage workflow (3 nodes as per AgenticVM pattern)."""
    graph = StateGraph(TriageState)

    graph.add_node("ingest_node", ingest_node)
    graph.add_node("analysis_node", analysis_node)
    graph.add_node("report_node", report_node)

    graph.set_entry_point("ingest_node")
    graph.add_edge("ingest_node", "analysis_node")
    graph.add_edge("analysis_node", "report_node")
    graph.add_edge("report_node", END)

    return graph


def run_triage(input_file: str) -> tuple[str, dict]:
    """Run the full triage pipeline on an EPSS-enriched JSON file."""
    graph = build_triage_graph()
    app = graph.compile()

    print(f"\n{'='*70}")
    print("LANGGRAPH TRIAGE AGENT — SSVC Vulnerability Prioritization")
    print(f"{'='*70}\n")

    initial_state: TriageState = {
        "input_file": input_file,
        "raw_cves": [],
        "kev_catalog": set(),
        "analyzed_cves": [],
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

    # Print per-CVE output for Act items (supervisor's expected format)
    act_items = [c for c in report_json["findings"] if c["priority"] == "CRITICAL"]
    if act_items:
        print(f"\n{'='*70}")
        print("CRITICAL FINDINGS (per-CVE detail)")
        print(f"{'='*70}")
        for item in act_items:
            print(json.dumps({
                "cve": item["cve"],
                "epss_score": item["epss_score"],
                "priority": item["priority"],
                "explanation": item["explanation"],
                "recommended_action": item["recommended_action"],
            }, indent=2))
            print()

    # Print summary
    summary = report_json.get("summary", {})
    print(f"{'='*70}")
    print("TRIAGE COMPLETE")
    print(f"{'='*70}")
    print(f"  Total CVEs:        {summary.get('total_cves', 0)}")
    print(f"  CRITICAL (Act):    {summary.get('critical_act', 0)}")
    print(f"  HIGH (Attend):     {summary.get('high_attend', 0)}")
    print(f"  MEDIUM (Track*):   {summary.get('medium_track_star', 0)}")
    print(f"  LOW (Track):       {summary.get('low_track', 0)}")
    print(f"  Alert reduction:   {summary.get('alert_reduction_pct', 0)}%")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
