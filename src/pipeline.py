"""
Pipeline orchestrator.

Runs the full flow in one process:
    scan (Trivy) -> enrich (EPSS) -> triage (SSVC + LLM) -> report + triage_run.json

Optional enrichers refine the triage decision when available:
    - Kubernetes deployment context, cluster-optional
    - Exploit-DB "public exploit exists" signal
    - Falco runtime-reachability signal (--falco <alert stream>)

Usage:
    python run.py pipeline nginx:latest
    python run.py pipeline nginx:latest --no-k8s --no-exploit
    python run.py pipeline nginx:latest --falco falco_alerts.json
    python run.py pipeline nginx:latest --gatekeeper
"""

import json
import sys

from src import config
from src.scanners.trivy_scanner import run_trivy_scan
from src.enrichment import epss_client
from src.triage.triage_agent import run_triage, save_reports
from src.triage.compact import write_triage_run


def _build_context_provider(use_k8s: bool, image: str):
    """Return a callable(cve)->K8s context dict, or None. Cluster-optional."""
    if not use_k8s:
        return None
    try:
        from src.context.k8s_context import make_context_provider
        return make_context_provider(image)
    except Exception as e:
        print(f"[*] K8s context unavailable ({e}); continuing without it")
        return None


def _build_exploit_lookup(use_exploit: bool):
    """Return a callable(cve_id)->bool for public-exploit existence, or None."""
    if not use_exploit:
        return None
    try:
        from src.enrichment.exploit_db import make_exploit_lookup
        return make_exploit_lookup()
    except Exception as e:
        print(f"[*] Exploit-DB lookup unavailable ({e}); continuing without it")
        return None


# Falco alert priorities, most-severe first (for picking the image's top signal).
_FALCO_PRIORITY_ORDER = {
    "EMERGENCY": 0, "ALERT": 1, "CRITICAL": 2, "ERROR": 3,
    "WARNING": 4, "NOTICE": 5, "INFORMATIONAL": 6, "DEBUG": 7,
}


def _build_runtime_provider(falco_path: str | None, falco_live: bool, image: str):
    """
    Build a callable(cve)->runtime signal dict from a Falco alert stream.

    Source is either a captured file (`falco_path`) or a live pull from the running
    cluster (`falco_live`). Image-level: the same signal applies to every finding in
    the image (Falco maps alerts to a pod/image, not to a CVE). Returns None if no
    Falco source is requested or it can't be read.
    """
    if not falco_path and not falco_live:
        return None
    try:
        from src.runtime.falco_client import (
            parse_falco_stream, alerts_for_image, capture_from_cluster)
        all_alerts = capture_from_cluster() if falco_live else parse_falco_stream(falco_path)
        alerts = alerts_for_image(all_alerts, image)
    except Exception as e:
        print(f"[*] Falco runtime signal unavailable ({e}); continuing without it")
        return None

    if not alerts:
        print(f"[*] Falco: no runtime alerts matched {image}; runtime signal is empty")
        runtime = {"available": True, "count": 0}
    else:
        top = sorted(alerts, key=lambda a: _FALCO_PRIORITY_ORDER.get(
            (a.get("priority") or "").upper(), 9))
        runtime = {
            "available": True,
            "count": len(alerts),
            "max_priority": top[0].get("priority", ""),
            "rules": [a.get("rule", "") for a in top[:5] if a.get("rule")],
        }
        print(f"[+] Falco runtime signal for {image}: {runtime['count']} alert(s), "
              f"max priority {runtime['max_priority'] or '-'}")

    def provider(_cve: dict) -> dict:
        return runtime

    return provider


def run_pipeline(image: str, use_k8s_context: bool = True, use_exploit_db: bool = True,
                 falco_path: str | None = None, falco_live: bool = False,
                 gatekeeper: bool = False):
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

    # Stage 3 — triage (with optional Kubernetes context + Exploit-DB signal)
    print("\n--- Stage 3/3: SSVC + LLM triage ---")
    context_provider = _build_context_provider(use_k8s_context, image)
    exploit_lookup = _build_exploit_lookup(use_exploit_db)
    runtime_provider = _build_runtime_provider(falco_path, falco_live, image)
    report_md, report_json = run_triage(
        str(epss_path),
        context_provider=context_provider,
        exploit_lookup=exploit_lookup,
        runtime_provider=runtime_provider,
    )
    md_path, json_path = save_reports(report_md, report_json, str(epss_path))

    # Per-image compact output. A single shared triage_run.json would be overwritten
    # by every image during scan-cluster, leaving only the last one; triage_run.json
    # is still refreshed as a "latest run" convenience copy.
    safe_image = image.replace("/", "_").replace(":", "_").replace("@", "_")
    run_path = write_triage_run(report_json, image,
                               path=config.RESULTS_DIR / f"triage_run_{safe_image}.json")
    (config.RESULTS_DIR / "triage_run.json").write_text(
        run_path.read_text(encoding="utf-8"), encoding="utf-8")

    print(f"\n[+] Markdown report: {md_path}")
    print(f"[+] JSON report:     {json_path}")
    print(f"[+] Compact output:  {run_path}")

    # Optional: emit OPA Gatekeeper policy YAML from the triage result, so one
    # pipeline run does scan -> decide -> (generate) enforce.
    if gatekeeper:
        try:
            from src.enforce.gatekeeper import run as run_gatekeeper
            gk_path = run_gatekeeper(str(run_path), image)
            print(f"[+] Gatekeeper policy: {gk_path}")
        except Exception as e:
            print(f"[*] Gatekeeper generation skipped ({e})")

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


# Kubernetes' own infrastructure namespaces. Skipped by default: scanning the
# control plane (etcd, apiserver, kube-proxy, ...) triples the runtime and buries
# the workloads the user actually deployed. --include-system opts back in.
SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease", "local-path-storage",
})


def run_scan_cluster(use_k8s_context: bool = True, use_exploit_db: bool = True,
                     falco_live: bool = False, namespace: str | None = None,
                     include_system: bool = False, falco_path: str | None = None):
    """
    Discover the images running in the cluster, triage each with K8s context and one
    cluster-wide Falco signal reused for every image, and write an aggregate report.
    Composes discover + pipeline + runtime reachability.

    Runtime signal source: `falco_path` (a captured alert file) takes precedence;
    otherwise `falco_live` captures from the cluster. System namespaces are skipped
    unless include_system is set (or `namespace` explicitly targets one).
    """
    from src.context.k8s_context import discover_pods

    inv = discover_pods(namespace=namespace)
    if not inv.get("available"):
        print("[!] scan-cluster needs a reachable Kubernetes cluster.")
        return None
    running = [p for p in inv["pods"] if p.get("phase") == "Running"]

    skipped_images: set[str] = set()
    if not include_system and namespace is None:
        kept = []
        for p in running:
            if p.get("namespace") in SYSTEM_NAMESPACES:
                skipped_images.update(p.get("images", []))
            else:
                kept.append(p)
        running = kept

    images = sorted({img for p in running for img in p.get("images", [])})
    skipped_images -= set(images)
    if not images:
        print("[*] No running images to scan.")
        return None
    print(f"\n{'#'*70}\n# SCAN-CLUSTER: {len(images)} running image(s)\n{'#'*70}")
    if skipped_images:
        print(f"[*] Skipped {len(skipped_images)} image(s) in system namespaces "
              f"({', '.join(sorted(SYSTEM_NAMESPACES))}); use --include-system to scan them.")

    # One Falco signal for the whole cluster, reused for every image. A captured
    # file wins over a live pull (the file path is what works when Falco can't emit
    # JSON on this host).
    falco_file = None
    if falco_path:
        falco_file = falco_path
        print(f"[*] Using Falco alerts from {falco_path} for runtime reachability")
    elif falco_live:
        from src.runtime.falco_client import run_live
        try:
            falco_file = str(run_live())
        except Exception as e:
            print(f"[*] Falco live capture failed ({e}); continuing without runtime signal")

    results = []
    for img in images:
        try:
            report = run_pipeline(img, use_k8s_context=use_k8s_context,
                                  use_exploit_db=use_exploit_db, falco_path=falco_file)
            results.append({"image": img, "summary": (report or {}).get("summary", {})})
        except Exception as e:
            print(f"[!] {img}: pipeline failed ({e})")
            results.append({"image": img, "error": str(e)})

    _write_cluster_report(results)
    return results


def _write_cluster_report(results: list[dict]) -> None:
    """Write the aggregate cluster-scan report (markdown + json)."""
    config.ensure_dirs()
    lines = ["# Cluster Scan Report", "",
             f"Images triaged: {len(results)}", "",
             "| Image | CVEs | Act | Attend | Track* | Track | Reduction |",
             "|-------|-----:|----:|-------:|-------:|------:|----------:|"]
    for r in results:
        if r.get("error"):
            lines.append(f"| `{r['image']}` | _error: {r['error']}_ |  |  |  |  |  |")
            continue
        s = r["summary"]
        lines.append(
            f"| `{r['image']}` | {s.get('total_cves', 0)} | {s.get('critical_act', 0)} | "
            f"{s.get('high_attend', 0)} | {s.get('medium_track_star', 0)} | "
            f"{s.get('low_track', 0)} | {s.get('alert_reduction_pct', 0)}% |")
    md_path = config.RESULTS_DIR / "scan_cluster_report.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json_path = config.RESULTS_DIR / "scan_cluster_report.json"
    json_path.write_text(json.dumps({"images": results}, indent=2), encoding="utf-8")
    print(f"\n{'='*70}\nSCAN-CLUSTER COMPLETE — {len(results)} image(s)\n{'='*70}")
    print(f"[+] Aggregate report: {md_path}")
    print(f"[+] JSON:             {json_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py pipeline <image>")
        sys.exit(1)
    run_pipeline(sys.argv[1])


if __name__ == "__main__":
    main()
