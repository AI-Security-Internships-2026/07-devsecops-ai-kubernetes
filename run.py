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
    run_pipeline(args.image, use_k8s_context=not args.no_k8s,
                 use_exploit_db=not args.no_exploit, falco_path=args.falco,
                 falco_live=args.falco_live, gatekeeper=args.gatekeeper)


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
    run_watch(interval=args.interval, status=args.status, stop=args.stop)


def cmd_chat(args):
    from src.chatbot.cli import run_chat
    run_chat()


def cmd_gatekeeper(args):
    from src.enforce.gatekeeper import run as run_gatekeeper
    run_gatekeeper(args.triage_json, args.image)


def cmd_falco_capture(args):
    from src.runtime.falco_client import run as run_falco, run_live
    if args.live:
        run_live(namespace=args.namespace)
    elif args.falco_output:
        run_falco(args.falco_output)
    else:
        print("[!] Provide a Falco JSON file, or use --live to pull from the cluster.")


def cmd_scan_cluster(args):
    from src.pipeline import run_scan_cluster
    run_scan_cluster(use_k8s_context=not args.no_k8s, use_exploit_db=not args.no_exploit,
                     falco_live=args.falco_live, namespace=args.namespace,
                     include_system=args.include_system, falco_path=args.falco)


def cmd_discover(args):
    import json as _json
    from src import config
    from src.context.k8s_context import discover_pods

    inv = discover_pods(namespace=args.namespace)
    if not inv.get("available"):
        print("[!] No reachable Kubernetes cluster (or the kubernetes package is missing).")
        return
    pods = inv["pods"]
    if not pods:
        print("[*] No pods found.")
        return

    print(f"\n{'NAMESPACE':<18} {'POD':<34} {'PHASE':<11} {'EXPOSURE':<12} {'PRIV':<5} IMAGE")
    print("-" * 108)
    for p in pods:
        img = p["images"][0] if p["images"] else "-"
        exposure = p["exposure_type"] or ("exposed" if p["exposed"] else "internal")
        priv = "yes" if p["privileged"] else "no"
        print(f"{p['namespace']:<18.18} {p['pod']:<34.34} {p['phase']:<11.11} "
              f"{exposure:<12.12} {priv:<5} {img}")

    running = sum(1 for p in pods if p["phase"] == "Running")
    exposed = sum(1 for p in pods if p["exposed"])
    privileged = sum(1 for p in pods if p["privileged"])
    print(f"\n[+] {len(pods)} pods ({running} Running) | {exposed} exposed | {privileged} privileged")

    config.ensure_dirs()
    out = config.RESULTS_DIR / "cluster_inventory.json"
    out.write_text(_json.dumps(inv, indent=2), encoding="utf-8")
    print(f"[+] Inventory written: {out}")


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
    pl.add_argument("--falco", default=None,
                    help="Falco JSON alert stream (file) to fold in as a runtime-reachability signal")
    pl.add_argument("--falco-live", action="store_true",
                    help="capture the Falco signal live from the running cluster (no file)")
    pl.add_argument("--gatekeeper", action="store_true",
                    help="also emit OPA Gatekeeper policy YAML from the triage result")
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
    w.add_argument("--status", action="store_true",
                   help="show whether a watcher is running + a summary")
    w.add_argument("--stop", action="store_true",
                   help="stop a running background watcher")
    w.set_defaults(func=cmd_watch)

    c = sub.add_parser("chat", help="Interactive CLI chatbot over the MCP tools")
    c.set_defaults(func=cmd_chat)

    gk = sub.add_parser("gatekeeper", help="Generate OPA Gatekeeper policy YAML from a triage report")
    gk.add_argument("triage_json", help="path to triage_run*.json or triage_report*.json")
    gk.add_argument("--image", default=None, help="override container image name")
    gk.set_defaults(func=cmd_gatekeeper)

    fc = sub.add_parser("falco-capture", help="Parse a Falco JSON alert stream (file, or --live from the cluster)")
    fc.add_argument("falco_output", nargs="?", default=None,
                    help="path to Falco JSON output (one JSON object per line)")
    fc.add_argument("--live", action="store_true",
                    help="capture straight from the running cluster's Falco pods (no file)")
    fc.add_argument("--namespace", default="falco",
                    help="Falco namespace for --live (default: falco)")
    fc.set_defaults(func=cmd_falco_capture)

    dc = sub.add_parser("discover", help="Discover pods in the cluster (image, status, exposure, privilege)")
    dc.add_argument("--namespace", default=None, help="limit to a single namespace")
    dc.set_defaults(func=cmd_discover)

    scl = sub.add_parser("scan-cluster",
                         help="Discover running images and triage each one (cluster-wide report)")
    scl.add_argument("--namespace", default=None, help="limit to a single namespace")
    scl.add_argument("--no-k8s", action="store_true", help="skip Kubernetes context enrichment")
    scl.add_argument("--no-exploit", action="store_true", help="skip Exploit-DB lookup")
    scl.add_argument("--falco", default=None,
                     help="Falco JSON alert stream (file) to fold in as runtime reachability per image")
    scl.add_argument("--falco-live", action="store_true",
                     help="capture Falco alerts live and fold in runtime reachability per image")
    scl.add_argument("--include-system", action="store_true",
                     help="also scan images in Kubernetes system namespaces (kube-system, ...)")
    scl.set_defaults(func=cmd_scan_cluster)

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
