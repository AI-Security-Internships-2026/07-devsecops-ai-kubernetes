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

import os
from concurrent.futures import ThreadPoolExecutor

from src.triage import ssvc
from src.triage.explain import get_llm, llm_analyze_cve, static_explanation


def _explain_concurrently(llm, wanted: list[dict], verbose: bool) -> dict:
    """
    Fetch explanations for the actionable CVEs in parallel.

    The calls are independent - one explanation per CVE, no shared state - and each
    is dominated by model latency, so running them sequentially left the pipeline
    waiting on a few hundred round trips. A local model on a contended GPU made that
    the slowest stage of a run by a wide margin.

    Concurrency is capped and configurable (LLM_CONCURRENCY, default 6): a shared
    GPU is not ours alone, and too many in-flight requests degrade everyone's
    throughput rather than improving ours. Order does not matter because results are
    keyed by CVE id, and a failed call simply falls back to the static explanation.
    """
    if not wanted:
        return {}
    try:
        workers = max(1, int(os.getenv('LLM_CONCURRENCY', '6')))
    except ValueError:
        workers = 6
    workers = min(workers, len(wanted))
    if verbose:
        print(f'    [*] Explaining {len(wanted)} actionable CVE(s) with {workers} '
              f'parallel request(s)...')

    def one(item):
        try:
            return item['cve_id'], llm_analyze_cve(llm, item['cve'], item['in_kev'])
        except Exception:
            return item['cve_id'], None

    out = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for cve_id, result in pool.map(one, wanted):
            if result:
                out[cve_id] = result
    if verbose:
        print(f'    [+] {len(out)}/{len(wanted)} explanation(s) generated')
    return out


def analyze_cves(
    cves: list[dict],
    kev_ids: set,
    context_provider=None,
    exploit_lookup=None,
    runtime_provider=None,
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
        runtime_provider: optional callable(cve)->Falco runtime signal dict
        llm: "auto" (auto-detect), an LLM instance, or None (static only)

    Returns:
        list of finding dicts (keys consumed by triage.report).
    """
    if llm == "auto":
        llm = get_llm()

    # Two passes. The decisions are pure rule arithmetic and stay sequential and
    # deterministic; the explanations are independent network calls, so they are
    # batched and run in parallel afterwards. Separating them also means the SSVC
    # result never depends on whether, or how fast, a model answered.
    decided = []
    for cve in cves:
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

        runtime = None
        if runtime_provider:
            try:
                runtime = runtime_provider(cve)
            except Exception:
                runtime = None

        result = ssvc.analyze(cve_with_kev, in_kev, context=context,
                              exploit_exists=exploit_exists, runtime=runtime)
        decided.append((cve, in_kev, result))

    # One explanation per distinct actionable CVE. Findings are per (CVE, package)
    # pair, so a CVE affecting several packages would otherwise be explained once per
    # package; the explanation describes the CVE, not the package instance.
    llm_cache: dict[str, dict] = {}
    if llm:
        wanted, seen = [], set()
        for cve, in_kev, result in decided:
            cve_id = cve["cve_id"]
            if result["priority"] in ("CRITICAL", "HIGH") and cve_id not in seen:
                seen.add(cve_id)
                wanted.append({"cve_id": cve_id, "cve": cve, "in_kev": in_kev})
        llm_cache = _explain_concurrently(llm, wanted, verbose)

    analyzed = []
    for cve, in_kev, result in decided:
        priority, decision, notes = result["priority"], result["decision"], result["notes"]
        llm_result = llm_cache.get(cve["cve_id"])
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
