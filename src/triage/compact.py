"""
Compact machine-readable triage output (`triage_run.json`).

Produces the exact schema the Week-5 issue requires, per finding:
    container image, CVE ID, CVSS severity, EPSS score, KEV status,
    final SSVC decision, decision rationale, execution timestamp,
    and any scanner/enrichment errors.

`to_triage_run()` is a pure transform of a triage report_json (so it works
whether the report came from the LangGraph agent or the langgraph-free
generator below — both use the same SSVC engine, so decisions are identical).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from src import config


def _rationale(finding: dict) -> str:
    """Human-readable decision rationale = context/exploit notes + explanation."""
    parts = []
    if finding.get("notes"):
        parts.append("; ".join(finding["notes"]))
    if finding.get("explanation"):
        parts.append(finding["explanation"])
    return " | ".join(p for p in parts if p)


def _packages(finding: dict) -> list[str]:
    out = []
    for p in finding.get("packages", []):
        s = p.get("package", "")
        if p.get("installed_version"):
            s += f"@{p['installed_version']}"
        if p.get("fixed_version"):
            s += f" -> {p['fixed_version']}"
        out.append(s)
    return out


def to_triage_run(report_json: dict, container_image: str, errors: list | None = None) -> dict:
    """Transform a triage report into the compact Week-5 schema (pure)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings = []
    for f in report_json.get("findings", []):
        findings.append({
            "container_image": container_image,
            "cve_id": f["cve"],
            "cvss_severity": f.get("severity", "UNKNOWN"),
            "cvss_score": f.get("cvss_score", 0.0),
            "epss_score": f.get("epss_score", 0.0),
            "kev_status": bool(f.get("in_kev", False)),
            "ssvc_decision": f.get("ssvc_decision"),
            "priority": f.get("priority"),
            "decision_rationale": _rationale(f),
            "affected_packages": _packages(f),
        })
    return {
        "execution_timestamp": now,
        "container_image": container_image,
        "source_scan": report_json.get("source_file"),
        "pipeline": {
            "scan": "trivy",
            "enrichment": ["epss", "cisa_kev"],
            "decision": "ssvc",
            "agent": "langgraph",
        },
        "summary": report_json.get("summary", {}),
        "errors": errors or [],
        "findings": findings,
    }


def write_triage_run(report_json: dict, container_image: str, errors: list | None = None,
                     path: str | Path | None = None) -> Path:
    """Write triage_run.json (default: experiments/results/triage_run.json)."""
    config.ensure_dirs()
    out_path = Path(path) if path else config.RESULTS_DIR / "triage_run.json"
    data = to_triage_run(report_json, container_image, errors)
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[+] Compact triage output saved: {out_path}")
    return out_path


def _derive_image_from_filename(epss_json_path: str) -> str:
    """Best-effort image name from an epss_enriched_trivy_<safe>.json filename."""
    stem = Path(epss_json_path).stem
    return stem.replace("epss_enriched_trivy_", "").replace("epss_enriched_", "")


def generate_from_enriched(epss_json_path: str, container_image: str | None = None,
                           use_llm: bool = True) -> tuple[dict, dict]:
    """
    Langgraph-free generation of (report_json, triage_run) from a real
    EPSS-enriched Trivy result. Uses the same SSVC engine as the agent, so the
    decisions match. Handy for producing the committed artifact without needing
    langgraph, and for local validation.
    """
    from src.enrichment.kev_client import fetch_kev_ids
    from src.triage import engine
    from src.triage.report import build_reports

    image = container_image or _derive_image_from_filename(epss_json_path)
    errors: list[dict] = []

    cves = json.loads(Path(epss_json_path).read_text(encoding="utf-8"))
    cves = [c for c in cves if c.get("epss_score", 0) > 0]

    kev_ids = fetch_kev_ids()
    if not kev_ids:
        errors.append({"stage": "cisa_kev", "error": "KEV catalog unavailable; decisions used EPSS/CVSS only"})

    llm = "auto" if use_llm else None
    analyzed = engine.analyze_cves(cves, kev_ids, llm=llm, verbose=False)
    _, report_json = build_reports(analyzed, epss_json_path)

    triage_run = to_triage_run(report_json, image, errors)
    return report_json, triage_run
