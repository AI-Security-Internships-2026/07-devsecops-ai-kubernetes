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
    run_pipeline(args.image, use_k8s_context=not args.no_k8s, use_exploit_db=not args.no_exploit)


def cmd_db_setup(args):
    from src.database.db import init_db
    path = init_db()
    print(f"[+] CVE intelligence database ready at: {path}")


def cmd_sbom(args):
    from src.database.sbom import generate_and_store
    generate_and_store(args.image)


def cmd_db_poll(args):
    from src.database import db
    db.init_db()
    if args.source in ("nvd", "all"):
        from src.database.pollers.nvd_poller import poll_nvd
        poll_nvd(hours=args.hours)
    if args.source in ("osv", "all"):
        from src.database.pollers.osv_poller import poll_osv
        poll_osv()


def cmd_watch(args):
    from src.database.watcher_agent import run_watch
    run_watch(interval=args.interval)


def cmd_chat(args):
    from src.chatbot.cli import run_chat
    run_chat()


def cmd_gatekeeper(args):
    from src.enforce.gatekeeper import run as run_gatekeeper
    run_gatekeeper(args.triage_json, args.image)


def cmd_falco_capture(args):
    from src.runtime.falco_client import run as run_falco
    run_falco(args.falco_output)


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
    pl.add_argument("--no-exploit", action="store_true", help="skip Exploit-DB lookup")
    pl.set_defaults(func=cmd_pipeline)

    ds = sub.add_parser("db-setup", help="Initialise the CVE intelligence database")
    ds.set_defaults(func=cmd_db_setup)

    sb = sub.add_parser("sbom", help="Generate + store a CycloneDX SBOM for an image")
    sb.add_argument("image", help="e.g. nginx:latest")
    sb.set_defaults(func=cmd_sbom)

    dp = sub.add_parser("db-poll", help="Pull latest CVEs into the database (NVD/OSV)")
    dp.add_argument("--source", choices=["nvd", "osv", "all"], default="all")
    dp.add_argument("--hours", type=int, default=24, help="NVD: look back this many hours")
    dp.set_defaults(func=cmd_db_poll)

    w = sub.add_parser("watch", help="Run the CVE-intelligence watcher (fresh-CVE alerts)")
    w.add_argument("--interval", type=int, default=None,
                   help="seconds between passes for continuous mode (default: one-shot)")
    w.set_defaults(func=cmd_watch)

    c = sub.add_parser("chat", help="Interactive CLI chatbot over the MCP tools")
    c.set_defaults(func=cmd_chat)

    gk = sub.add_parser("gatekeeper", help="Generate OPA Gatekeeper policy YAML from a triage report")
    gk.add_argument("triage_json", help="path to triage_run*.json or triage_report*.json")
    gk.add_argument("--image", default=None, help="override container image name")
    gk.set_defaults(func=cmd_gatekeeper)

    fc = sub.add_parser("falco-capture", help="Parse a Falco JSON alert stream into normalized alerts")
    fc.add_argument("falco_output", help="path to Falco JSON output (one JSON object per line)")
    fc.set_defaults(func=cmd_falco_capture)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except RuntimeError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
