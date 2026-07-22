"""
Triage report generation (pure — no LangGraph / network).

Groups analyzed findings by CVE ID (a single CVE often affects several
packages in one image) so each CVE appears ONCE, with its affected packages
aggregated. This fixes the duplicate-CVE bug where e.g. CVE-2023-45288 showed
up four times in one report.
"""

from datetime import datetime, timezone
from pathlib import Path

_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def group_findings(analyzed: list[dict]) -> list[dict]:
    """
    Collapse per-package findings into one entry per CVE ID.

    Affected packages are aggregated into a `packages` list. Priority/decision
    take the most severe seen for that CVE (they are normally identical).
    """
    grouped: dict[str, dict] = {}

    for f in analyzed:
        cve_id = f["cve"]
        pkg = {
            "package": f.get("package", "unknown"),
            "installed_version": f.get("installed_version", ""),
            "fixed_version": f.get("fixed_version", ""),
        }

        if cve_id not in grouped:
            grouped[cve_id] = {
                "cve": cve_id,
                "priority": f["priority"],
                "ssvc_decision": f["ssvc_decision"],
                "epss_score": f.get("epss_score", 0.0),
                "cvss_score": f.get("cvss_score", 0.0),
                "severity": f.get("severity", "UNKNOWN"),
                "in_kev": f.get("in_kev", False),
                "explanation": f.get("explanation", ""),
                "recommended_action": f.get("recommended_action", ""),
                "notes": list(f.get("notes", [])),
                "packages": [pkg],
            }
        else:
            entry = grouped[cve_id]
            # keep the most severe priority if they somehow differ
            if _PRIORITY_ORDER.get(f["priority"], 3) < _PRIORITY_ORDER.get(entry["priority"], 3):
                entry["priority"] = f["priority"]
                entry["ssvc_decision"] = f["ssvc_decision"]
            # dedupe packages by (name, installed_version)
            key = (pkg["package"], pkg["installed_version"])
            if key not in {(p["package"], p["installed_version"]) for p in entry["packages"]}:
                entry["packages"].append(pkg)
            for n in f.get("notes", []):
                if n not in entry["notes"]:
                    entry["notes"].append(n)

    ordered = sorted(
        grouped.values(),
        key=lambda c: (_PRIORITY_ORDER.get(c["priority"], 3), -c["epss_score"]),
    )
    return ordered


def summarize(grouped: list[dict]) -> dict:
    """Count unique CVEs per priority + alert-reduction percentage."""
    total = len(grouped)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for c in grouped:
        counts[c["priority"]] = counts.get(c["priority"], 0) + 1
    deferred = counts["MEDIUM"] + counts["LOW"]
    return {
        "total_cves": total,
        "critical_act": counts["CRITICAL"],
        "high_attend": counts["HIGH"],
        "medium_track_star": counts["MEDIUM"],
        "low_track": counts["LOW"],
        "alert_reduction_pct": round(deferred / max(total, 1) * 100, 1),
    }


def _packages_line(packages: list[dict]) -> str:
    """Render the affected-package list for one CVE."""
    parts = []
    for p in packages:
        s = f"`{p['package']}`"
        if p["installed_version"]:
            s += f" (`{p['installed_version']}`)"
        if p["fixed_version"]:
            s += f" -> `{p['fixed_version']}`"
        parts.append(s)
    return ", ".join(parts)


def _detail_block(md: list[str], item: dict) -> None:
    kev = " | **CISA KEV: YES**" if item["in_kev"] else ""
    md.append(f"### {item['cve']}")
    md.append(f"**Affected package(s):** {_packages_line(item['packages'])}  ")
    md.append(f"**EPSS:** {item['epss_score']:.3f} | **CVSS:** {item['cvss_score']:.1f}{kev}  ")
    if item.get("notes"):
        md.append(f"**Context:** {'; '.join(item['notes'])}  ")
    md.append(f"**Explanation:** {item['explanation']}  ")
    md.append(f"**Action:** {item['recommended_action']}")
    md.append("")


def build_markdown(grouped: list[dict], source_name: str, summary: dict, now: str) -> str:
    act = [c for c in grouped if c["priority"] == "CRITICAL"]
    attend = [c for c in grouped if c["priority"] == "HIGH"]

    md: list[str] = []
    md.append("# Vulnerability Triage Report")
    md.append(f"\n**Generated:** {now}")
    md.append(f"**Source:** `{source_name}`")
    md.append(f"**Unique CVEs analyzed:** {summary['total_cves']}")
    md.append(f"**Alert reduction:** {summary['alert_reduction_pct']}%")
    md.append("")

    md.append("## Executive Summary")
    md.append("")
    md.append(
        f"Of {summary['total_cves']} unique vulnerabilities analyzed, "
        f"**{summary['critical_act']} require immediate action** (CRITICAL) and "
        f"**{summary['high_attend']} should be addressed this sprint** (HIGH). "
        f"{summary['alert_reduction_pct']:.0f}% of findings are safe to defer, reducing "
        f"alert fatigue to {summary['critical_act'] + summary['high_attend']} actionable items."
    )
    md.append("")

    md.append("## Decision Breakdown")
    md.append("")
    md.append("| Priority | SSVC Decision | Count | Action Required |")
    md.append("|----------|---------------|-------|-----------------|")
    md.append(f"| CRITICAL | Act | {summary['critical_act']} | Fix immediately — block deployment |")
    md.append(f"| HIGH | Attend | {summary['high_attend']} | Fix this sprint |")
    md.append(f"| MEDIUM | Track* | {summary['medium_track_star']} | Monitor — reassess next quarter |")
    md.append(f"| LOW | Track | {summary['low_track']} | Safe to defer |")
    md.append("")

    if act:
        md.append("## CRITICAL — Immediate Action Required")
        md.append("")
        for item in act:
            _detail_block(md, item)

    if attend:
        md.append("## HIGH — Fix This Sprint")
        md.append("")
        for item in attend[:15]:
            _detail_block(md, item)
        if len(attend) > 15:
            md.append(f"*...and {len(attend) - 15} more HIGH priority CVEs.*\n")

    md.append("## Methodology")
    md.append("")
    md.append("This report uses **CISA SSVC** with **EPSS** exploit probability scoring:")
    md.append("- **CRITICAL/Act**: EPSS >= 0.1 (10%+ exploitation probability) OR in CISA KEV")
    md.append("- **HIGH/Attend**: EPSS >= 0.01 AND (CVSS >= 7.0 OR CRITICAL/HIGH severity)")
    md.append("- **MEDIUM/Track***: EPSS >= 0.01 (moderate probability, lower impact)")
    md.append("- **LOW/Track**: EPSS < 0.01 (very low exploitation probability)")
    md.append("")
    md.append("*Reference: AgenticVM (Arifin et al., 2026) — multi-agent vulnerability management.*")

    return "\n".join(md)


def build_reports(analyzed: list[dict], source_name: str) -> tuple[str, dict]:
    """Group findings, then produce (markdown, json_dict). The single entry point."""
    grouped = group_findings(analyzed)
    summary = summarize(grouped)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report_markdown = build_markdown(grouped, source_name, summary, now)
    report_json = {
        "generated_at": now,
        "source_file": Path(source_name).name,
        "summary": summary,
        "findings": grouped,
    }
    return report_markdown, report_json
