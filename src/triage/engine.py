"""
Shared analysis loop (langgraph-free).

The single source of truth for turning EPSS-enriched CVEs into analyzed
findings: SSVC decision (+ optional K8s context / exploit signals) plus a
per-CVE explanation. Both the LangGraph agent (triage_agent.analysis_node) and
the compact exporter (compact.generate_from_enriched) call this, so their
decisions are always identical.

Imports only langgraph-free modules (ssvc, explain), so it is usable and
testable without langgraph installed.
"""

from src.triage import ssvc
from src.triage.explain import get_llm, llm_analyze_cve, static_explanation


def analyze_cves(
    cves: list[dict],
    kev_ids: set,
    context_provider=None,
    exploit_lookup=None,
    llm="auto",
    verbose: bool = True,
) -> list[dict]:
    """
    Analyze a list of EPSS-enriched CVE dicts into triage findings.

    Args:
        cves: EPSS-enriched CVE dicts (from epss_client output)
        kev_ids: set of CISA KEV CVE IDs
        context_provider: optional callable(cve)->K8s context dict (P3)
        exploit_lookup: optional callable(cve_id)->bool (P4)
        llm: "auto" (auto-detect), an LLM instance, or None (static only)

    Returns:
        list of finding dicts (keys consumed by triage.report).
    """
    if llm == "auto":
        llm = get_llm()

    analyzed = []
    for i, cve in enumerate(cves):
        in_kev = cve["cve_id"] in kev_ids
        cve_with_kev = {**cve, "in_kev": in_kev}

        exploit_exists = False
        if exploit_lookup:
            try:
                exploit_exists = bool(exploit_lookup(cve["cve_id"]))
            except Exception:
                exploit_exists = False

        context = None
        if context_provider:
            try:
                context = context_provider(cve)
            except Exception:
                context = None

        result = ssvc.analyze(cve_with_kev, in_kev, context=context, exploit_exists=exploit_exists)
        priority, decision, notes = result["priority"], result["decision"], result["notes"]

        llm_result = None
        if llm and priority in ("CRITICAL", "HIGH"):
            llm_result = llm_analyze_cve(llm, cve, in_kev)
            if llm_result and verbose:
                print(f"    [{i+1}/{len(cves)}] {cve['cve_id']} -> {priority} (LLM)")
        if not llm_result:
            llm_result = static_explanation(cve, priority, in_kev)

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
            "ssvc_decision": decision,
            "in_kev": in_kev,
            "notes": notes,
            "explanation": llm_result["explanation"],
            "recommended_action": llm_result["recommended_action"],
        })

    return analyzed


def decision_counts(analyzed: list[dict]) -> dict:
    """Count findings by SSVC decision (pre-dedup)."""
    counts = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
    for a in analyzed:
        counts[a["ssvc_decision"]] = counts.get(a["ssvc_decision"], 0) + 1
    return counts
