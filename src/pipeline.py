"""
Pipeline orchestrator.

Runs the full flow in one process:
    scan (Trivy) -> enrich (EPSS) -> triage (SSVC + LLM) -> report + triage_run.json

Optional enrichers refine the triage decision when available:
    - Kubernetes deployment context (P3), cluster-optional

Usage:
    python run.py pipeline nginx:latest
    python run.py pipeline nginx:latest --no-k8s
"""

import sys

from src.scanners.trivy_scanner import run_trivy_scan
from src.enrichment import epss_client
from src.triage.triage_agent import run_triage, save_reports
from src.triage.compact import write_triage_run


def _build_context_provider(use_k8s: bool, image: str):
    """Return a callable(cve)->K8s context dict, or None. Cluster-optional (P3)."""
    if not use_k8s:
        return None
    try:
        from src.context.k8s_context import make_context_provider
        return make_context_provider(image)
    except Exception as e:
        print(f"[*] K8s context unavailable ({e}); continuing without it")
        return None


def run_pipeline(image: str, use_k8s_context: bool = True):
    """Scan -> enrich -> triage for a single image. Returns the JSON report dict."""
    print(f"\n{'#'*70}\n# PIPELINE: {image}\n{'#'*70}")

    # Stage 1 — scan
    print("\n--- Stage 1/3: Trivy scan ---")
    _, trivy_path = run_trivy_scan(image)

    # Stage 2 — enrich
    print("\n--- Stage 2/3: EPSS enrichment ---")
    enriched, epss_path = epss_client.run(str(trivy_path))
    if not enriched or epss_path is None:
        print("[!] No CVEs to triage. Stopping.")
        return None

    # Stage 3 — triage (with optional Kubernetes context)
    print("\n--- Stage 3/3: SSVC + LLM triage ---")
    context_provider = _build_context_provider(use_k8s_context, image)
    report_md, report_json = run_triage(str(epss_path), context_provider=context_provider)
    md_path, json_path = save_reports(report_md, report_json, str(epss_path))
    run_path = write_triage_run(report_json, image)

    print(f"\n[+] Markdown report: {md_path}")
    print(f"[+] JSON report:     {json_path}")
    print(f"[+] Compact output:  {run_path}")

    s = report_json.get("summary", {})
    print(f"\n{'='*70}\nPIPELINE COMPLETE — {image}\n{'='*70}")
    print(f"  Unique CVEs:       {s.get('total_cves', 0)}")
    print(f"  CRITICAL (Act):    {s.get('critical_act', 0)}")
    print(f"  HIGH (Attend):     {s.get('high_attend', 0)}")
    print(f"  MEDIUM (Track*):   {s.get('medium_track_star', 0)}")
    print(f"  LOW (Track):       {s.get('low_track', 0)}")
    print(f"  Alert reduction:   {s.get('alert_reduction_pct', 0)}%")
    print("=" * 70)
    return report_json


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py pipeline <image>")
        sys.exit(1)
    run_pipeline(sys.argv[1])


if __name__ == "__main__":
    main()
