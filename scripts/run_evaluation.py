#!/usr/bin/env python3
"""
Reproducible publication evaluation (issue #22).

One command per experiment family, reading the frozen dataset and writing a
self-describing run directory. No paper number should ever be copied out of an
individual JSON file by hand.

    python scripts/run_evaluation.py --experiment historical-main
    python scripts/run_evaluation.py --experiment historical-threshold-sweep
    python scripts/run_evaluation.py --experiment determinism-check
    python scripts/run_evaluation.py --list

Output lands in experiments/publication/<run-id>/ with config, environment, summary
metrics, confidence intervals, statistical tests and the table sources.
"""

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.baselines import build_baselines                      # noqa: E402
from src.dataset import historical                             # noqa: E402
from src.evaluation import ladder as L                         # noqa: E402
from src.evaluation.runner import (EvaluationRun, verify_determinism,  # noqa: E402
                                   write_run)

# EPSS thresholds to sweep — the range issue #24 experiment 6D prescribes.
SWEEP_THRESHOLDS = (0.01, 0.025, 0.05, 0.075, 0.10, 0.15, 0.20)

EXPERIMENTS = {
    "historical-main": "All baselines on the historical dataset, with CIs and McNemar",
    "historical-threshold-sweep": "EPSS threshold sensitivity (issue #24, experiment 6D)",
    "noise-ladder": "Progressive noise reduction, one signal layer at a time (issue #26)",
    "determinism-check": "Run the comparison twice and diff the decisions",
}


def load_records(snapshots, eligible_only=True):
    """Load and concatenate snapshots. Ineligible rows are excluded from scoring."""
    rows = []
    for snap in snapshots:
        loaded = historical.load(snap)
        rows.extend([r for r in loaded if r["eligible"]] if eligible_only else loaded)
    return rows


def load_manifest():
    path = historical.HISTORICAL_DIR / "manifest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def fmt_pct(value, digits=1):
    return "n/a" if value is None else f"{value:.{digits}%}"


def run_main(args, records, manifest):
    run = EvaluationRun("historical-main", records, args.label, run_id=args.run_id)
    summary = run.run()

    print(f"\n{'method':<16}{'actionable':>12}{'reduction':>11}{'recall':>9}"
          f"{'P@20':>7}{'R@100':>8}")
    print("-" * 63)
    for name, s in summary.items():
        print(f"{name:<16}{s['actionable']:>12,}{fmt_pct(s['workload_reduction']):>11}"
              f"{fmt_pct(s['recall']):>9}{s['precision_at_20']:>7.2f}"
              f"{s['recall_at_100']:>8.2f}")

    cis = tests = None
    if not args.no_ci:
        print(f"\n[*] Bootstrap CIs ({args.resamples} resamples, clustered by cve_id)...")
        cis = run.confidence_intervals(args.resamples)
        print(f"\n{'method':<16}{'recall 95% CI':<24}{'reduction 95% CI':<24}")
        print("-" * 64)
        for name in summary:
            r, w = cis[name]["recall"], cis[name]["workload_reduction"]
            rc = (f"[{fmt_pct(r['lower'])}, {fmt_pct(r['upper'])}]"
                  if r["lower"] is not None else "n/a")
            wc = f"[{fmt_pct(w['lower'], 2)}, {fmt_pct(w['upper'], 2)}]"
            print(f"{name:<16}{rc:<24}{wc:<24}")
        print(f"\n[*] Recall CIs rest on {len(run.positives)} confirmed positives, which is "
              f"why they are wide.\n    Reduction CIs rest on {len(run.population):,} "
              f"records, which is why they are tight.")

    if args.reference:
        tests = run.paired_tests(args.reference)
        print(f"\n[*] McNemar vs {args.reference} (outcome: caught a confirmed-exploited CVE)")
        print(f"\n{'comparison':<34}{'b':>5}{'c':>5}{'p':>12}  test")
        print("-" * 72)
        for key, t in tests.items():
            print(f"{key:<34}{t['b']:>5}{t['c']:>5}{t['p_value']:>12.4g}  {t['method']}")

    out = write_run(run, summary, cis, tests, dataset_manifest=manifest,
                    config_used=vars(args) | {"snapshots": [str(s) for s in args.snapshots]},
                    write_raw=not args.no_raw)
    print(f"\n[+] {out}")
    return out


def run_sweep(args, records, manifest):
    """Experiment 6D — vary the EPSS threshold, report the whole curve."""
    positives = {r["cve_id"] for r in records
                 if str(r.get(args.label)).lower() in ("true", "1", "yes")}
    print(f"\nEPSS threshold sweep — {len(records):,} records, {len(positives)} positives")
    print(f"\n{'threshold':>10}{'actionable':>12}{'reduction':>11}{'recall':>9}"
          f"{'efficiency':>12}")
    print("-" * 54)

    rows = []
    for t in SWEEP_THRESHOLDS:
        run = EvaluationRun(f"sweep-{t}", records, args.label,
                            methods={"epss_only": build_baselines(
                                epss_only={"threshold": t})["epss_only"]})
        s = run.run()["epss_only"]
        rows.append({"threshold": t, **s})
        print(f"{t:>10}{s['actionable']:>12,}{fmt_pct(s['workload_reduction']):>11}"
              f"{fmt_pct(s['recall']):>9}"
              f"{(f'{s['efficiency']:.4%}' if s['efficiency'] else 'n/a'):>12}")

    print("\n[*] Report the whole curve, not the best point — #24 forbids cherry-picking "
          "the\n    optimum, and the chosen operating point has to be justified against it.")

    out_dir = (Path("experiments/publication") /
               (args.run_id or datetime.now().strftime("%Y%m%d-%H%M%S") + "-sweep"))
    (out_dir / "tables").mkdir(parents=True, exist_ok=True)
    import csv
    with open(out_dir / "tables" / "threshold_sweep.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=sorted({k for r in rows for k in r}),
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"\n[+] {out_dir}")
    return out_dir


def run_ladder(args, records, manifest):
    """
    Progressive noise reduction (issue #26) — one signal layer switched on at a time.

    Reports the marginal effect of every layer rather than a single end-to-end figure,
    so a reviewer can see which signal actually removes the noise and what recall each
    removal costs.
    """
    methods = L.build_ladder()
    run = EvaluationRun("noise-ladder", records, args.label, methods=methods,
                        run_id=args.run_id or
                        datetime.now().strftime("%Y%m%d-%H%M%S") + "-ladder")
    summary = run.run()
    rows = L.ladder_rows(summary)

    print(f"\nProgressive noise reduction — {len(run.population):,} records, "
          f"{len(run.positives)} positives, label {args.label}")
    print(f"\n{'':>3} {'layer':<26}{'actionable':>12}{'reduction':>11}{'recall':>9}"
          f"{'d(queue)':>12}{'d(recall)':>11}")
    print("-" * 87)
    for r in rows:
        da = ("" if r["delta_actionable"] is None
              else f"{r['delta_actionable']:+,}")
        dr = ("" if r["delta_recall"] is None
              else f"{r['delta_recall']:+.1%}")
        marker = " " if r["cumulative"] else "."
        print(f"{r['rung']:>3}{marker}{r['label']:<26}{r['actionable']:>12,}"
              f"{fmt_pct(r['workload_reduction']):>11}{fmt_pct(r['recall']):>9}"
              f"{da:>12}{dr:>11}")

    print("\n  . = single-signal alternative, measured against L0 rather than the rung "
          "above it.")

    flat = [r for r in L.inert_rungs(rows) if r["status"] != "inert as documented"]
    inert = [r for r in L.inert_rungs(rows) if r["status"] == "inert as documented"]
    if inert:
        print("\n[*] Rungs that cannot move on this dataset, as documented in "
              "src/evaluation/ladder.py:")
        for r in inert:
            print(f"      {r['rung']} {r['label']:<24} {r['inert']}")
    if flat:
        print("\n[!] Rungs that did not behave as documented — investigate before "
              "citing this table:")
        for r in flat:
            print(f"      {r['rung']} {r['label']:<24} {r['status']}")

    collapsed = L.collapsed_rows(rows)
    print(f"\n[*] Five-stage view for the waterfall figure:")
    for r in collapsed:
        da = "" if r["delta_actionable"] is None else f"{r['delta_actionable']:+,}"
        print(f"      {r['stage']:<20}{r['actionable']:>12,}"
              f"{fmt_pct(r['workload_reduction']):>11}{da:>12}")

    out_dir = Path("experiments/publication") / run.run_id
    (out_dir / "tables").mkdir(parents=True, exist_ok=True)
    import csv
    for fname, data in (("noise_ladder.csv", rows),
                        ("noise_ladder_collapsed.csv", collapsed)):
        with open(out_dir / "tables" / fname, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(data[0]), extrasaction="ignore")
            w.writeheader()
            w.writerows(data)

    write_run(run, summary, None, None, dataset_manifest=manifest,
              config_used=vars(args) | {"snapshots": [str(s) for s in args.snapshots],
                                        "rungs": [r.key for r in L.RUNGS]},
              write_raw=False, out_dir=None)
    print(f"\n[+] {out_dir}")
    return out_dir


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment", default="historical-main", choices=list(EXPERIMENTS))
    ap.add_argument("--list", action="store_true", help="list experiments and exit")
    ap.add_argument("--snapshots", nargs="+",
                    type=lambda s: datetime.strptime(s, "%Y-%m-%d").date(),
                    default=list(historical.DEFAULT_SNAPSHOTS))
    ap.add_argument("--label", default="later_kev_90d",
                    help="outcome column (default: %(default)s)")
    ap.add_argument("--reference", default="epss_only",
                    help="method to run paired tests against; '' to skip")
    ap.add_argument("--resamples", type=int, default=2000)
    ap.add_argument("--no-ci", action="store_true", help="skip bootstrap CIs (faster)")
    ap.add_argument("--no-raw", action="store_true",
                    help="skip raw_results.csv (it is large)")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    if args.list:
        for name, desc in EXPERIMENTS.items():
            print(f"  {name:<30} {desc}")
        return 0

    print("=" * 66)
    print(f"{args.experiment}")
    print(f"snapshots : {', '.join(s.isoformat() for s in args.snapshots)}")
    print(f"label     : {args.label}")
    print("=" * 66)

    try:
        records = load_records(args.snapshots)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        print("[*] Build it first: python scripts/build_dataset.py --historical")
        return 1

    manifest = load_manifest()
    print(f"[+] {len(records):,} eligible records loaded")

    if args.experiment == "determinism-check":
        result = verify_determinism(records[:20000], args.label)
        print(f"\n{'DETERMINISTIC' if result['deterministic'] else 'NON-DETERMINISTIC'}"
              f" over {result['methods_checked']} methods")
        if result["mismatches"]:
            for m in result["mismatches"]:
                print(f"  {m['method']}: {m['differing_rows']} differing rows")
            return 1
        return 0

    if args.experiment == "historical-threshold-sweep":
        run_sweep(args, records, manifest)
        return 0

    if args.experiment == "noise-ladder":
        run_ladder(args, records, manifest)
        return 0

    run_main(args, records, manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
