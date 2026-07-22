"""
LangGraph Triage Agent
Auto-generates a triage report from EPSS-prioritized CVE data using
SSVC decision logic + LLM-powered per-CVE explanations.

This implements Stage 3 of the pipeline:
    Trivy (scan) -> EPSS (enrich) -> THIS AGENT (triage) -> Report (output)

Architecture (ref: AgenticVM 2026):
    StateGraph with 3 nodes:
        ingest_node   - reads EPSS-prioritized CVE JSON + CISA KEV
        analysis_node - SSVC classification (+ optional K8s context / exploit
                        signals) + LLM risk explanation per CVE
        report_node   - grouped, deduped triage report (Markdown + JSON)

Deterministic decision logic lives in src/triage/ssvc.py; report rendering in
src/triage/report.py. This module orchestrates them via LangGraph and adds the
LLM explanation layer.

Usage:
    python run.py triage <epss_enriched_json>
    python -m src.triage.triage_agent experiments/results/epss_enriched_trivy_nginx_latest.json
"""

import json
import sys
from pathlib import Path
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

from src import config
from src.enrichment.kev_client import fetch_kev_ids
from src.triage import engine
from src.triage.explain import get_llm
from src.triage.report import build_reports

load_dotenv()

OUTPUT_DIR = config.RESULTS_DIR


# ---------------------------------------------------------------------------
# State definition — flows through the graph
# ---------------------------------------------------------------------------

class TriageState(TypedDict):
    input_file: str
    raw_cves: list[dict]
    kev_catalog: set
    context_provider: object  # optional callable(image/pkg) -> context dict; P3
    exploit_lookup: object    # optional callable(cve_id) -> bool; P4
    analyzed_cves: list[dict]
    report_markdown: str
    report_json: dict


# ---------------------------------------------------------------------------
# Node 1: ingest_node
# ---------------------------------------------------------------------------

def ingest_node(state: TriageState) -> dict:
    """Read EPSS-prioritized CVE JSON and fetch the CISA KEV catalog."""
    input_path = Path(state["input_file"])
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        sys.exit(1)

    cves = json.loads(input_path.read_text())
    print(f"[+] Ingested {len(cves)} CVEs from {input_path.name}")

    actionable = [c for c in cves if c.get("epss_score", 0) > 0]
    print(f"[+] {len(actionable)} CVEs have EPSS scores > 0")

    print("[*] Fetching CISA KEV catalog...")
    kev_ids = fetch_kev_ids()
    if kev_ids:
        print(f"[+] KEV catalog: {len(kev_ids)} known exploited CVEs")
    else:
        print("[*] Continuing without KEV data")

    return {"raw_cves": actionable, "kev_catalog": kev_ids}


# ---------------------------------------------------------------------------
# Node 2: analysis_node
# ---------------------------------------------------------------------------

def analysis_node(state: TriageState) -> dict:
    """Classify each CVE with SSVC (+ optional context/exploit) and explain it.

    Delegates the per-CVE work to the shared engine (single source of truth,
    also used by the compact exporter).
    """
    llm = get_llm()
    if not llm:
        print("[*] No LLM API key found — using static explanations")
        print("[*] Set GROQ_API_KEY (free: console.groq.com) or GOOGLE_API_KEY for LLM analysis")

    analyzed = engine.analyze_cves(
        state["raw_cves"],
        state["kev_catalog"],
        context_provider=state.get("context_provider"),
        exploit_lookup=state.get("exploit_lookup"),
        llm=llm,
    )

    counts = engine.decision_counts(analyzed)
    print("\n[+] Analysis complete (per-finding, pre-dedup):")
    print(f"    CRITICAL / Act:    {counts['Act']}")
    print(f"    HIGH / Attend:     {counts['Attend']}")
    print(f"    MEDIUM / Track*:   {counts['Track*']}")
    print(f"    LOW / Track:       {counts['Track']}")

    return {"analyzed_cves": analyzed}


# ---------------------------------------------------------------------------
# Node 3: report_node
# ---------------------------------------------------------------------------

def report_node(state: TriageState) -> dict:
    """Generate grouped/deduped triage report (Markdown + JSON)."""
    report_markdown, report_json = build_reports(
        state["analyzed_cves"], state["input_file"]
    )
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


def run_triage(input_file: str, context_provider=None, exploit_lookup=None) -> tuple[str, dict]:
    """
    Run the full triage pipeline on an EPSS-enriched JSON file.

    Optional:
        context_provider(cve_dict) -> K8s context dict   (P3)
        exploit_lookup(cve_id) -> bool                    (P4)
    """
    app = build_triage_graph().compile()

    print(f"\n{'='*70}")
    print("LANGGRAPH TRIAGE AGENT — SSVC Vulnerability Prioritization")
    print(f"{'='*70}\n")

    initial_state: TriageState = {
        "input_file": input_file,
        "raw_cves": [],
        "kev_catalog": set(),
        "context_provider": context_provider,
        "exploit_lookup": exploit_lookup,
        "analyzed_cves": [],
        "report_markdown": "",
        "report_json": {},
    }

    final_state = app.invoke(initial_state)
    return final_state["report_markdown"], final_state["report_json"]


def save_reports(report_md: str, report_json: dict, input_file: str) -> tuple[Path, Path]:
    """Write markdown + json reports to the results dir; return their paths."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    input_name = Path(input_file).stem.replace("epss_enriched_", "")

    md_path = OUTPUT_DIR / f"triage_report_{input_name}.md"
    md_path.write_text(report_md, encoding="utf-8")

    json_path = OUTPUT_DIR / f"triage_report_{input_name}.json"
    json_path.write_text(json.dumps(report_json, indent=2, default=str), encoding="utf-8")
    return md_path, json_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py triage <epss_enriched_json>")
        sys.exit(1)

    input_file = sys.argv[1]
    report_md, report_json = run_triage(input_file)

    md_path, json_path = save_reports(report_md, report_json, input_file)
    print(f"\n[+] Markdown report saved: {md_path}")
    print(f"[+] JSON report saved: {json_path}")

    summary = report_json.get("summary", {})
    print(f"\n{'='*70}")
    print("TRIAGE COMPLETE")
    print(f"{'='*70}")
    print(f"  Unique CVEs:       {summary.get('total_cves', 0)}")
    print(f"  CRITICAL (Act):    {summary.get('critical_act', 0)}")
    print(f"  HIGH (Attend):     {summary.get('high_attend', 0)}")
    print(f"  MEDIUM (Track*):   {summary.get('medium_track_star', 0)}")
    print(f"  LOW (Track):       {summary.get('low_track', 0)}")
    print(f"  Alert reduction:   {summary.get('alert_reduction_pct', 0)}%")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
