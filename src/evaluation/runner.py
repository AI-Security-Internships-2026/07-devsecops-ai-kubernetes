"""
Reproducible evaluation runner (issue #22).

One command has to reproduce every main result from frozen inputs, and the manuscript
must never depend on copying counts out of individual JSON files by hand. So this module
owns the whole path: load the frozen dataset, run every method over identical records,
compute metrics centrally, and write a self-describing run directory.

Design decisions worth knowing
------------------------------
**Metrics are computed in one place.** Each method returns decisions; none computes its
own score. A method that measured itself could measure itself differently.

**The environment is recorded, not assumed.** Git SHA, tool versions, EPSS model version
and KEV catalog date all land in `environment.json`. Two runs that disagree should be
explicable from that file alone.

**Determinism is checkable.** The decision path is pure, so the same frozen inputs must
yield byte-identical decisions. `verify_determinism` runs the comparison twice and
diffs — a regression here invalidates every paired significance test, because those
assume the pairing is stable.
"""

import csv
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from src import config
from src.baselines import ACTIONABLE, build_baselines, signal_matrix
from src.evaluation import metrics as M

PUBLICATION_DIR = config.ROOT / "experiments" / "publication"

# Reported at several K so the top-of-queue behaviour is visible, not just the aggregate.
DEFAULT_KS = (10, 20, 50, 100)


# ------------------------------------------------------------------ environment

def _cmd(args: list[str]) -> str:
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else "unavailable"
    except Exception:
        return "unavailable"


def capture_environment(dataset_manifest: dict | None = None) -> dict:
    """
    Everything needed to explain why two runs might differ.

    Tool versions are probed rather than declared: a recorded version that was never
    checked is worse than none, because it looks authoritative.
    """
    env = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": _cmd(["git", "rev-parse", "HEAD"]),
        "git_branch": _cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        "git_dirty": bool(_cmd(["git", "status", "--porcelain"]) not in ("", "unavailable")),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "trivy": _cmd(["trivy", "--version"]),
        "kubectl": _cmd(["kubectl", "version", "--client", "-o", "json"])[:120],
    }
    if dataset_manifest:
        env["dataset"] = {
            "snapshots": dataset_manifest.get("snapshots"),
            "outcome_windows_days": dataset_manifest.get("outcome_windows_days"),
            "epss_model_versions": {
                d: v.get("model_version")
                for d, v in (dataset_manifest.get("sources", {})
                             .get("epss", {}).get("files", {}) or {}).items()},
            "kev_catalog_version": (dataset_manifest.get("sources", {})
                                    .get("kev", {}).get("catalog_version")),
            "totals": dataset_manifest.get("totals"),
        }
    return env


# ------------------------------------------------------------------- the runner

class EvaluationRun:
    """
    One experiment: a set of methods over one frozen record set, with one label column.

    `label_field` selects the outcome window (`later_kev_90d` and friends), so the same
    records can be evaluated at several horizons without rebuilding anything.
    """

    def __init__(self, experiment: str, records: list[dict], label_field: str,
                 methods: dict | None = None, ks=DEFAULT_KS, run_id: str | None = None):
        self.experiment = experiment
        self.records = records
        self.label_field = label_field
        self.methods = methods if methods is not None else build_baselines()
        self.ks = tuple(ks)
        self.run_id = run_id or datetime.now().strftime("%Y%m%d-%H%M%S")

        self.population = {r["cve_id"] for r in records}
        self.positives = {r["cve_id"] for r in records if _truthy(r.get(label_field))}
        self.results: dict[str, list] = {}
        self.timings: dict[str, float] = {}

    def run(self) -> dict:
        """Run every method and return per-method summary metrics."""
        summary = {}
        for name, method in self.methods.items():
            start = time.perf_counter()
            decisions = method.run(self.records)
            elapsed_ms = (time.perf_counter() - start) * 1000

            self.results[name] = decisions
            self.timings[name] = elapsed_ms

            flagged = {d.cve_id for d in decisions if d.decision == ACTIONABLE}
            ranked = [d.cve_id for d in decisions]

            summary[name] = {
                "experiment": self.experiment,
                "method": name,
                "label_field": self.label_field,
                **M.classification_metrics(flagged, self.positives, self.population),
                **M.ranking_metrics(ranked, self.positives, self.ks),
                "latency_ms": round(elapsed_ms, 1),
                "records_per_second": round(len(self.records) / (elapsed_ms / 1000), 0)
                if elapsed_ms else None,
            }
        return summary

    def confidence_intervals(self, n_resamples: int = 2000) -> dict:
        """
        Clustered bootstrap CIs on recall and workload reduction per method.

        Each CVE is collapsed to one boolean before resampling, so a draw always takes a
        whole CVE and correlated snapshot rows can never count as independent evidence —
        the requirement the dataset manifest records. Collapsing first also makes the
        statistic a plain proportion, which is vectorisable.

        The two intervals behave very differently and that is informative rather than a
        defect: recall rests on ~92 confirmed positives and comes out wide, while
        reduction rests on ~900k records and comes out extremely tight. Reporting both
        makes clear which claims the data can actually support.
        """
        out = {}
        population = sorted(self.population)
        positives = sorted(self.positives)
        for name, decisions in self.results.items():
            flagged = {d.cve_id for d in decisions if d.decision == ACTIONABLE}
            out[name] = {
                "recall": M.bootstrap_proportion_ci(
                    [cve in flagged for cve in positives], n_resamples),
                "workload_reduction": M.bootstrap_proportion_ci(
                    [cve not in flagged for cve in population], n_resamples),
            }
        return out

    def paired_tests(self, reference: str) -> dict:
        """
        McNemar against one reference method, on which positives each one caught.

        Only prespecified comparisons should be run — #22 warns against applying tests
        mechanically, and testing every pair would invite multiple-comparison problems
        that we would then have to correct for.
        """
        if reference not in self.results:
            raise ValueError(f"reference method {reference!r} was not run")
        ref_caught = self._caught(reference)
        out = {}
        for name in self.results:
            if name == reference:
                continue
            out[f"{name}_vs_{reference}"] = {
                "method_a": name, "method_b": reference,
                "outcome": "caught a confirmed-exploited CVE",
                **M.mcnemar(self._caught(name), ref_caught, self.positives),
            }
        return out

    def _caught(self, method: str) -> set:
        flagged = {d.cve_id for d in self.results[method] if d.decision == ACTIONABLE}
        return flagged & self.positives

    # --------------------------------------------------------------- outputs

    def raw_rows(self) -> list[dict]:
        """Tidy long-form rows — one per (method, cve). The source for every table."""
        labels = {r["cve_id"]: _truthy(r.get(self.label_field)) for r in self.records}
        rows = []
        for name, decisions in self.results.items():
            for d in decisions:
                rows.append({
                    "experiment_id": self.experiment,
                    "run_id": self.run_id,
                    "method": name,
                    "cve_id": d.cve_id,
                    "score": round(d.score, 6),
                    "rank": d.rank,
                    "is_actionable": d.decision == ACTIONABLE,
                    "priority": d.priority,
                    "outcome_label": labels.get(d.cve_id, False),
                    "label_field": self.label_field,
                })
        return rows


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def write_run(run: EvaluationRun, summary: dict, cis: dict | None = None,
              tests: dict | None = None, out_dir: Path | None = None,
              dataset_manifest: dict | None = None, config_used: dict | None = None,
              write_raw: bool = True) -> Path:
    """
    Write the self-describing run directory #22 specifies.

    `raw_results.csv` can be very large (methods x records), so it is optional — but the
    summary and statistics are always written, because those are what the paper cites.
    """
    base = (out_dir or PUBLICATION_DIR) / run.run_id
    for sub in ("tables", "figures", "logs"):
        (base / sub).mkdir(parents=True, exist_ok=True)

    (base / "environment.json").write_text(
        json.dumps(capture_environment(dataset_manifest), indent=2), encoding="utf-8")
    (base / "config.json").write_text(
        json.dumps(config_used or {"experiment": run.experiment,
                                   "label_field": run.label_field,
                                   "methods": list(run.methods),
                                   "ks": list(run.ks)}, indent=2), encoding="utf-8")

    summary_path = base / "summary_metrics.csv"
    rows = list(summary.values())
    if rows:
        fields = sorted({k for r in rows for k in r})
        with open(summary_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)

    if cis:
        (base / "confidence_intervals.json").write_text(
            json.dumps(cis, indent=2), encoding="utf-8")
    if tests:
        test_rows = list(tests.values())
        if test_rows:
            fields = sorted({k for r in test_rows for k in r})
            with open(base / "statistical_tests.csv", "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                w.writerows(test_rows)

    if write_raw:
        raw = run.raw_rows()
        if raw:
            with open(base / "raw_results.csv", "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(raw[0]))
                w.writeheader()
                w.writerows(raw)

    # Figure B1's source, generated from the baseline classes.
    with open(base / "tables" / "signal_coverage.csv", "w", newline="",
              encoding="utf-8") as fh:
        matrix = signal_matrix()
        w = csv.DictWriter(fh, fieldnames=list(matrix[0]))
        w.writeheader()
        w.writerows(matrix)

    return base


def verify_determinism(records: list[dict], label_field: str, methods=None) -> dict:
    """
    Run the same comparison twice and confirm identical decisions.

    Required by #22, but it also protects the significance tests: McNemar pairs items
    between methods, and if either run's decisions drifted the pairing would be
    meaningless.
    """
    methods = methods if methods is not None else build_baselines()
    first = EvaluationRun("determinism", records, label_field, methods)
    first.run()
    second = EvaluationRun("determinism", records, label_field, build_baselines())
    second.run()

    mismatches = []
    for name in first.results:
        a = [(d.cve_id, d.decision, round(d.score, 9), d.rank) for d in first.results[name]]
        b = [(d.cve_id, d.decision, round(d.score, 9), d.rank) for d in second.results[name]]
        if a != b:
            differing = sum(1 for x, y in zip(a, b) if x != y)
            mismatches.append({"method": name, "differing_rows": differing})

    return {"deterministic": not mismatches, "methods_checked": len(first.results),
            "mismatches": mismatches}
