#!/usr/bin/env python3
"""
evaluate_triage.py - deterministic evaluation of the triage pipeline (Week 9, P1).

Reads committed triage_run_*.json files and produces the paper's Section-IV tables
with NO network, NO repo imports, NO LLM - pure functions of the frozen JSON, so
"results match committed files exactly" (issue #10 checklist).

It answers four questions:
  1. Volume        - how many CVEs, and how many our tool marks actionable.
  2. Baselines     - CVSS-only vs EPSS-only vs Ours: actionable count + reduction.
  3. KEV recall    - of the known-exploited CVEs, how many each method keeps in
                     its actionable set (are we dropping the real threats?).
  4. Context/runtime effect - how many findings the K8s-context + Falco-runtime
                     refinements escalated/de-escalated, and the Act-tier before/after
                     (the escalation-capping fix as a reliability result).

Usage:
    python evaluate_triage.py [DIR | file.json ...]      # default DIR: current dir
    python evaluate_triage.py ~/Dev/07-devsecops-ai-kubernetes/experiments/results
    python evaluate_triage.py <dir> --out eval           # write eval.md + eval.json

Definitions (stated so the paper can cite them):
    Our tool  actionable = priority in {CRITICAL, HIGH}        (SSVC Act + Attend)
    CVSS-only actionable = cvss_severity in {CRITICAL, HIGH}   (patch HIGH+ policy)
    EPSS-only actionable = epss_score >= 0.1                   (FIRST/CISA "act" threshold)
    KEV recall(method)   = |actionable(method) intersect KEV| / |KEV|
    Act-before           = Act-after - (escalations into CRITICAL)
                                     + (de-escalations out of CRITICAL)
"""

import argparse
import glob
import json
import os
import sys

ACTIONABLE_SEVERITIES = {"CRITICAL", "HIGH"}   # CVSS-only "patch this" set
EPSS_ACT = 0.1                                 # EPSS-only actionable threshold


def load_reports(paths):
    """Expand dirs/globs to triage_run_*.json files (excluding the bare 'latest' copy)."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "triage_run_*.json")))
        elif any(ch in p for ch in "*?["):
            files += sorted(glob.glob(p))
        else:
            files.append(p)
    seen, out = set(), []
    for f in files:
        f = os.path.abspath(f)
        if os.path.basename(f) == "triage_run.json":   # bare copy duplicates a per-image file
            continue
        if f not in seen and os.path.isfile(f):
            seen.add(f)
            out.append(f)
    return out


def norm(f):
    """Normalize one finding to the fields we score."""
    return {
        "cve": f.get("cve_id") or f.get("cve") or "",
        "severity": (f.get("cvss_severity") or f.get("severity") or "UNKNOWN").upper(),
        "epss": float(f.get("epss_score") or 0.0),
        "kev": bool(f.get("kev_status", f.get("in_kev", False))),
        "priority": (f.get("priority") or "").upper(),
        "rationale": (f.get("decision_rationale") or "").lower(),
    }


def evaluate_one(path):
    data = json.load(open(path, encoding="utf-8"))
    image = data.get("container_image") or os.path.basename(path)
    findings = [norm(f) for f in data.get("findings", [])]
    total = len(findings)

    kev = [f for f in findings if f["kev"]]
    n_kev = len(kev)

    def recall(pred):
        if n_kev == 0:
            return None
        return sum(1 for f in kev if pred(f)) / n_kev

    methods = {
        "CVSS-only (sev>=HIGH)": lambda f: f["severity"] in ACTIONABLE_SEVERITIES,
        "EPSS-only (>=0.1)":     lambda f: f["epss"] >= EPSS_ACT,
        "Ours (Act+Attend)":     lambda f: f["priority"] in ACTIONABLE_SEVERITIES,
    }
    method_rows = {}
    for name, pred in methods.items():
        flagged = sum(1 for f in findings if pred(f))
        method_rows[name] = {
            "actionable": flagged,
            "reduction_pct": round((1 - flagged / total) * 100, 1) if total else 0.0,
            "kev_recall": recall(pred),
        }

    # Context/runtime effect, parsed from the recorded rationale notes.
    #
    # A finding can be escalated and then clamped back by the total-escalation cap,
    # in which case its rationale contains BOTH notes and it did not actually reach
    # Act. Counting the escalation note alone would overstate the movement, so a
    # capped-out-of-CRITICAL finding is excluded.
    def escalated_into_crit(f):
        r = f["rationale"]
        if "escalated" not in r or "de-escalated" in r or "->critical" not in r:
            return False
        return "capped critical->" not in r

    esc_to_crit = sum(1 for f in findings if escalated_into_crit(f))
    deesc_from_crit = sum(1 for f in findings
                          if "de-escalated" in f["rationale"]
                          and "critical->" in f["rationale"])
    by_context = sum(1 for f in findings
                     if "internet-facing" in f["rationale"] or "privileged" in f["rationale"])
    by_runtime = sum(1 for f in findings if "falco" in f["rationale"])
    by_exploit = sum(1 for f in findings if "public exploit" in f["rationale"])
    capped = sum(1 for f in findings if "capped " in f["rationale"])

    # Runtime ATTRIBUTION (issue #17). The runtime signal only escalates a finding
    # when the alert's process/file evidence resolves to a package that finding
    # affects; otherwise it is recorded and ignored. Reporting both counts keeps the
    # paper from implying the link always exists.
    rt_attributed = sum(1 for f in findings if "which this cve affects" in f["rationale"])
    rt_unattributed = sum(1 for f in findings if "not attributable" in f["rationale"])
    rt_seen = rt_attributed + rt_unattributed
    rt_rate = (rt_attributed / rt_seen) if rt_seen else None

    act_after = sum(1 for f in findings if f["priority"] == "CRITICAL")
    act_before = act_after - esc_to_crit + deesc_from_crit

    return {
        "image": image,
        "file": os.path.basename(path),
        "total_cves": total,
        "summary": data.get("summary", {}),
        "kev_total": n_kev,
        "methods": method_rows,
        "context_runtime": {
            "escalated_to_critical": esc_to_crit,
            "deescalated_from_critical": deesc_from_crit,
            "act_before": act_before,
            "act_after": act_after,
            "by_context": by_context,
            "by_runtime": by_runtime,
            "by_exploit": by_exploit,
            "capped": capped,
            "runtime_attributed": rt_attributed,
            "runtime_unattributed": rt_unattributed,
            "runtime_attribution_rate": rt_rate,
        },
    }


def fmt_recall(r):
    return "n/a" if r is None else "%.0f%%" % (r * 100)


def render_markdown(results):
    L = ["# Triage Evaluation\n",
         "Images evaluated: %d  -  definitions in the script header.\n" % len(results)]

    L.append("## 1. Volume & alert reduction (our tool)\n")
    L.append("| Image | CVEs | Act | Attend | Track* | Track | Reduction |")
    L.append("|-------|-----:|----:|-------:|-------:|------:|----------:|")
    for r in results:
        s = r["summary"]
        L.append("| `%s` | %d | %s | %s | %s | %s | %s%% |" % (
            r["image"], r["total_cves"], s.get("critical_act", 0),
            s.get("high_attend", 0), s.get("medium_track_star", 0),
            s.get("low_track", 0), s.get("alert_reduction_pct", 0)))

    L.append("\n## 2. Baseline comparison - actionable set size & reduction\n")
    L.append("Smaller actionable set = less analyst load. Read alongside section 3 (recall).\n")
    for r in results:
        L.append("\n**%s** (%d CVEs)\n" % (r["image"], r["total_cves"]))
        L.append("| Method | Actionable | Reduction | KEV recall |")
        L.append("|--------|-----------:|----------:|-----------:|")
        for name, m in r["methods"].items():
            L.append("| %s | %d | %s%% | %s |" % (
                name, m["actionable"], m["reduction_pct"], fmt_recall(m["kev_recall"])))

    L.append("\n## 3. KEV recall (ground truth = CISA KEV)\n")
    L.append("Does each method keep the *known-exploited* CVEs in its actionable set? "
             "A method that reduces volume but drops KEV items is worse, not better.\n")
    L.append("| Image | KEV CVEs | CVSS-only | EPSS-only | Ours |")
    L.append("|-------|---------:|:---------:|:---------:|:----:|")
    for r in results:
        m = r["methods"]
        L.append("| `%s` | %d | %s | %s | %s |" % (
            r["image"], r["kev_total"],
            fmt_recall(m["CVSS-only (sev>=HIGH)"]["kev_recall"]),
            fmt_recall(m["EPSS-only (>=0.1)"]["kev_recall"]),
            fmt_recall(m["Ours (Act+Attend)"]["kev_recall"])))

    L.append("\n## 4. Context / runtime effect on the Act tier\n")
    L.append("How the K8s-context + Falco-runtime refinements re-ranked findings "
             "(the escalation-capping fix keeps this bounded - at most one level each).\n")
    L.append("| Image | Act before | Act after | Escalated->CRIT | De-escalated | Capped | via context | via runtime | via exploit |")
    L.append("|-------|-----------:|----------:|----------------:|-------------:|-------:|------------:|------------:|------------:|")
    for r in results:
        c = r["context_runtime"]
        L.append("| `%s` | %d | %d | %d | %d | %d | %d | %d | %d |" % (
            r["image"], c["act_before"], c["act_after"],
            c["escalated_to_critical"], c["deescalated_from_critical"],
            c["capped"], c["by_context"], c["by_runtime"], c["by_exploit"]))

    L.append("\n## 5. Runtime attribution (issue #17)\n")
    L.append("The runtime signal escalates a finding only when the Falco alert's "
             "process/file evidence resolves to a package that finding affects. "
             "Alerts that cannot be attributed are recorded and ignored, so this "
             "table states how often the link was actually established.\n")
    L.append("| Image | Attributed | Not attributable | Attribution rate |")
    L.append("|-------|-----------:|-----------------:|-----------------:|")
    for r in results:
        c = r["context_runtime"]
        rate = c["runtime_attribution_rate"]
        L.append("| `%s` | %d | %d | %s |" % (
            r["image"], c["runtime_attributed"], c["runtime_unattributed"],
            "n/a" if rate is None else "%.0f%%" % (rate * 100)))

    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Deterministic triage evaluation (P1).")
    ap.add_argument("paths", nargs="*", default=["."],
                    help="triage_run_*.json files, or a dir/glob containing them (default: .)")
    ap.add_argument("--out", default=None,
                    help="basename to write <out>.md and <out>.json (default: print only)")
    args = ap.parse_args()

    files = load_reports(args.paths or ["."])
    if not files:
        print("[!] No triage_run_*.json files found. Point me at experiments/results/.",
              file=sys.stderr)
        sys.exit(1)

    results = [evaluate_one(f) for f in files]
    md = render_markdown(results)
    print(md)

    if args.out:
        with open(args.out + ".md", "w", encoding="utf-8") as fh:
            fh.write(md)
        with open(args.out + ".json", "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print("[+] Wrote %s.md and %s.json" % (args.out, args.out))


if __name__ == "__main__":
    main()
