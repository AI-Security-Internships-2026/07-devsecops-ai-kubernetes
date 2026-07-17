#!/usr/bin/env python3
"""
DevSecOps AI Pipeline — unified CLI entry point.

    python run.py scan <image>              # Trivy scan -> JSON
    python run.py enrich <trivy_json>       # add EPSS scores
    python run.py triage <epss_json>        # SSVC + LLM triage report + triage_run.json
    python run.py pipeline <image>          # scan -> enrich -> triage (all in one)

Each subcommand lazy-imports its dependencies, so `--help` works even if the
optional libs (langgraph, etc.) aren't installed yet.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def cmd_scan(args):
    from src.scanners.trivy_scanner import run_trivy_scan, extract_cves, print_summary
    scan_results, output_path = run_trivy_scan(args.image, args.output)
    cves = extract_cves(scan_results)
    print_summary(cves)
    unique = sorted({c["cve_id"] for c in cves if c["cve_id"].startswith("CVE-")})
    print(f"\n[*] {len(unique)} unique CVE IDs extracted.")
    print(f"[*] Next: python run.py enrich {output_path}")


def cmd_enrich(args):
    from src.enrichment import epss_client
    epss_client.run(args.trivy_json)


def cmd_triage(args):
    from src.triage.triage_agent import run_triage, save_reports
    from src.triage.compact import write_triage_run, _derive_image_from_filename
    report_md, report_json = run_triage(args.epss_json)
    md_path, json_path = save_reports(report_md, report_json, args.epss_json)
    print(f"\n[+] Markdown report saved: {md_path}")
    print(f"[+] JSON report saved: {json_path}")
    image = args.image or _derive_image_from_filename(args.epss_json)
    write_triage_run(report_json, image)
    _print_triage_summary(report_json)


def cmd_pipeline(args):
    from src.pipeline import run_pipeline
    run_pipeline(args.image, use_k8s_context=not args.no_k8s)


def _print_triage_summary(report_json: dict) -> None:
    summary = report_json.get("summary", {})
    print(f"\n{'='*70}\nTRIAGE COMPLETE\n{'='*70}")
    print(f"  Unique CVEs:       {summary.get('total_cves', 0)}")
    print(f"  CRITICAL (Act):    {summary.get('critical_act', 0)}")
    print(f"  HIGH (Attend):     {summary.get('high_attend', 0)}")
    print(f"  MEDIUM (Track*):   {summary.get('medium_track_star', 0)}")
    print(f"  LOW (Track):       {summary.get('low_track', 0)}")
    print(f"  Alert reduction:   {summary.get('alert_reduction_pct', 0)}%")
    print("=" * 70)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run.py", description="DevSecOps AI vulnerability triage pipeline")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Run a Trivy scan on a container image")
    s.add_argument("image", help="e.g. nginx:latest")
    s.add_argument("output", nargs="?", default=None, help="optional output JSON path")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("enrich", help="Enrich a Trivy JSON with EPSS scores")
    e.add_argument("trivy_json", help="path to trivy_*.json")
    e.set_defaults(func=cmd_enrich)

    t = sub.add_parser("triage", help="Run SSVC + LLM triage on EPSS-enriched JSON")
    t.add_argument("epss_json", help="path to epss_enriched_*.json")
    t.add_argument("--image", default=None, help="container image name for triage_run.json")
    t.set_defaults(func=cmd_triage)

    pl = sub.add_parser("pipeline", help="Full pipeline: scan -> enrich -> triage")
    pl.add_argument("image", help="e.g. nginx:latest")
    pl.add_argument("--no-k8s", action="store_true", help="skip Kubernetes context enrichment")
    pl.set_defaults(func=cmd_pipeline)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
