"""
Evaluation runner (issue #22).

The runner is what turns decisions into paper numbers, so the tests focus on the
properties that would corrupt results silently: metrics computed centrally rather than
per-method, determinism (without which paired tests are meaningless), and a run
directory that describes itself well enough to explain a disagreement between runs.

Offline — synthetic records, no dataset and no network.
"""

import csv
import json

import pytest

from src.baselines import build_baselines
from src.evaluation.runner import (EvaluationRun, capture_environment,
                                   verify_determinism, write_run)


def records(n=200, positives=("CVE-0", "CVE-1", "CVE-2")):
    """
    Synthetic population where EPSS correlates with the outcome, so a method that reads
    EPSS should beat one that ignores it — otherwise the test proves nothing.
    """
    out = []
    for i in range(n):
        is_pos = f"CVE-{i}" in positives
        out.append({
            "cve_id": f"CVE-{i}",
            "epss_score": 0.9 if is_pos else (0.001 if i % 2 else 0.02),
            "cvss_score": 9.0 if is_pos else 5.0,
            "cvss_severity": "CRITICAL" if is_pos else "MEDIUM",
            "kev_at_snapshot": False,
            "public_exploit_at_snapshot": is_pos,
            "later_kev_90d": is_pos,
            "eligible": True,
        })
    return out


class TestRun:
    def test_runs_every_method_on_identical_records(self):
        run = EvaluationRun("t", records(), "later_kev_90d")
        summary = run.run()
        assert set(summary) == set(build_baselines())
        # Every method must have scored the same population, or the comparison is void.
        assert {s["population"] for s in summary.values()} == {200}

    def test_identifies_positives_from_the_label_column(self):
        run = EvaluationRun("t", records(), "later_kev_90d")
        assert run.positives == {"CVE-0", "CVE-1", "CVE-2"}

    def test_label_column_selects_the_outcome_window(self):
        """Same records, different horizon — no rebuild required."""
        rows = records()
        for r in rows:
            r["later_kev_30d"] = False
        run = EvaluationRun("t", rows, "later_kev_30d")
        assert run.positives == set()

    def test_csv_string_labels_are_parsed(self):
        rows = records()
        for r in rows:
            r["later_kev_90d"] = "True" if r["cve_id"] == "CVE-0" else "False"
        assert EvaluationRun("t", rows, "later_kev_90d").positives == {"CVE-0"}

    def test_epss_method_beats_a_blind_one_on_recall(self):
        """Sanity on the harness: if this fails, the metrics are not wired to the data."""
        summary = EvaluationRun("t", records(), "later_kev_90d").run()
        assert summary["epss_only"]["recall"] == 1.0

    def test_summary_carries_classification_and_ranking_metrics(self):
        s = EvaluationRun("t", records(), "later_kev_90d").run()["epss_only"]
        for key in ("recall", "precision_lower_bound", "workload_reduction",
                    "precision_at_20", "recall_at_100", "latency_ms"):
            assert key in s

    def test_reports_coverage_and_efficiency_aliases(self):
        s = EvaluationRun("t", records(), "later_kev_90d").run()["epss_only"]
        assert s["coverage"] == s["recall"]
        assert s["efficiency"] == s["precision_lower_bound"]


class TestConfidenceIntervals:
    def test_brackets_the_point_estimate(self):
        run = EvaluationRun("t", records(), "later_kev_90d")
        run.run()
        ci = run.confidence_intervals(n_resamples=200)["epss_only"]["recall"]
        assert ci["lower"] <= ci["point"] <= ci["upper"]

    def test_resamples_clusters_not_rows(self):
        """#22 requires the unit to be documented; the paper has to state it."""
        run = EvaluationRun("t", records(), "later_kev_90d")
        run.run()
        ci = run.confidence_intervals(n_resamples=100)["epss_only"]["recall"]
        assert "cve_id" in ci["resampling_unit"]

    def test_recall_ci_is_wider_than_reduction_ci(self):
        """
        Recall rests on few positives and reduction on the whole population, so recall
        must be the less certain of the two. If they came out similar, the CIs would be
        keyed to the wrong denominators.

        The positives here are deliberately mixed — some above the EPSS threshold and
        some below — so recall is not saturated. A method that catches every positive
        gives a legitimately zero-width interval, which would test nothing.
        """
        rows = records(200, ("CVE-0", "CVE-1", "CVE-2", "CVE-3", "CVE-4"))
        for r in rows:                       # half the positives fall below threshold
            if r["cve_id"] in ("CVE-3", "CVE-4"):
                r["epss_score"] = 0.001
                r["public_exploit_at_snapshot"] = False
                r["cvss_score"] = 4.0
                r["cvss_severity"] = "MEDIUM"
        run = EvaluationRun("t", rows, "later_kev_90d")
        run.run()
        ci = run.confidence_intervals(n_resamples=400)["epss_only"]
        assert 0 < ci["recall"]["point"] < 1, "fixture must not saturate recall"
        recall_w = ci["recall"]["upper"] - ci["recall"]["lower"]
        red_w = ci["workload_reduction"]["upper"] - ci["workload_reduction"]["lower"]
        assert recall_w > red_w

    def test_saturated_recall_gives_a_zero_width_interval(self):
        """
        Not a defect: if a method flags every confirmed positive, every resample of those
        positives also scores 1.0. Worth pinning so it is not later mistaken for a bug.
        """
        run = EvaluationRun("t", records(), "later_kev_90d")
        run.run()
        ci = run.confidence_intervals(n_resamples=100)["epss_only"]["recall"]
        assert ci["point"] == 1.0
        assert ci["lower"] == ci["upper"] == 1.0


class TestPairedTests:
    def test_compares_each_method_to_the_reference(self):
        run = EvaluationRun("t", records(), "later_kev_90d")
        run.run()
        tests = run.paired_tests("epss_only")
        assert "cvss_only_vs_epss_only" in tests
        assert "epss_only_vs_epss_only" not in tests      # no self-comparison

    def test_unknown_reference_is_rejected(self):
        run = EvaluationRun("t", records(), "later_kev_90d")
        run.run()
        with pytest.raises(ValueError, match="reference method"):
            run.paired_tests("nonexistent")

    def test_records_the_outcome_being_tested(self):
        """A p-value without a stated outcome is uninterpretable."""
        run = EvaluationRun("t", records(), "later_kev_90d")
        run.run()
        t = run.paired_tests("epss_only")["cvss_only_vs_epss_only"]
        assert t["outcome"]
        assert "method_a" in t and "method_b" in t


class TestDeterminism:
    def test_repeated_runs_agree(self):
        """
        Required by #22, and load-bearing for the significance tests: McNemar pairs items
        between methods, so drifting decisions would make the pairing meaningless.
        """
        result = verify_determinism(records(), "later_kev_90d")
        assert result["deterministic"] is True
        assert result["mismatches"] == []
        assert result["methods_checked"] == 5


class TestOutputs:
    def test_raw_rows_are_long_form(self):
        run = EvaluationRun("t", records(20, ("CVE-0",)), "later_kev_90d")
        run.run()
        rows = run.raw_rows()
        assert len(rows) == 20 * 5          # records x methods
        for key in ("experiment_id", "method", "cve_id", "rank", "is_actionable",
                    "outcome_label"):
            assert key in rows[0]

    def test_write_run_produces_the_expected_tree(self, tmp_path):
        run = EvaluationRun("t", records(50, ("CVE-0",)), "later_kev_90d",
                            run_id="testrun")
        summary = run.run()
        cis = run.confidence_intervals(n_resamples=50)
        tests = run.paired_tests("epss_only")
        base = write_run(run, summary, cis, tests, out_dir=tmp_path)

        for name in ("environment.json", "config.json", "summary_metrics.csv",
                     "confidence_intervals.json", "statistical_tests.csv",
                     "raw_results.csv"):
            assert (base / name).exists(), name
        for sub in ("tables", "figures", "logs"):
            assert (base / sub).is_dir()
        assert (base / "tables" / "signal_coverage.csv").exists()

    def test_summary_csv_has_one_row_per_method(self, tmp_path):
        run = EvaluationRun("t", records(30, ("CVE-0",)), "later_kev_90d", run_id="r")
        summary = run.run()
        base = write_run(run, summary, out_dir=tmp_path, write_raw=False)
        with open(base / "summary_metrics.csv", encoding="utf-8") as fh:
            assert len(list(csv.DictReader(fh))) == 5

    def test_raw_results_can_be_skipped(self, tmp_path):
        """It is methods x records; on the real dataset that is millions of rows."""
        run = EvaluationRun("t", records(10, ("CVE-0",)), "later_kev_90d", run_id="r")
        base = write_run(run, run.run(), out_dir=tmp_path, write_raw=False)
        assert not (base / "raw_results.csv").exists()


class TestEnvironment:
    def test_records_what_would_explain_a_disagreement(self):
        env = capture_environment()
        for key in ("timestamp", "git_commit", "git_branch", "python", "platform",
                    "machine"):
            assert key in env

    def test_folds_in_dataset_provenance(self):
        manifest = {
            "snapshots": ["2026-01-01"],
            "outcome_windows_days": [30, 60, 90],
            "sources": {"epss": {"files": {"2026-01-01": {"model_version": "v2025.03.14"}}},
                        "kev": {"catalog_version": "2026.09.11"}},
            "totals": {"rows": 10},
        }
        env = capture_environment(manifest)
        assert env["dataset"]["epss_model_versions"]["2026-01-01"] == "v2025.03.14"
        assert env["dataset"]["kev_catalog_version"] == "2026.09.11"

    def test_written_environment_is_valid_json(self, tmp_path):
        run = EvaluationRun("t", records(10, ("CVE-0",)), "later_kev_90d", run_id="r")
        base = write_run(run, run.run(), out_dir=tmp_path, write_raw=False)
        assert json.loads((base / "environment.json").read_text(encoding="utf-8"))


class TestUnitOfAnalysis:
    """
    The unit is (cve_id, snapshot), not the CVE.

    A CVE evaluated at three snapshots is three separate predictions with different
    signals, and in the real dataset 34 CVEs have a 90-day outcome that differs between
    snapshots. Keying metrics on cve_id alone merged ~598k rows and OR'd those labels
    together, inflating recall.
    """

    def _multi_snapshot(self):
        """Same CVE, two snapshots, opposite outcomes and opposite EPSS."""
        return [
            {"cve_id": "CVE-A", "snapshot_date": "2025-09-01", "epss_score": 0.9,
             "cvss_score": 5.0, "cvss_severity": "MEDIUM", "kev_at_snapshot": False,
             "public_exploit_at_snapshot": False, "later_kev_90d": False},
            {"cve_id": "CVE-A", "snapshot_date": "2026-01-01", "epss_score": 0.001,
             "cvss_score": 5.0, "cvss_severity": "MEDIUM", "kev_at_snapshot": False,
             "public_exploit_at_snapshot": False, "later_kev_90d": True},
        ]

    def test_same_cve_at_two_snapshots_is_two_units(self):
        run = EvaluationRun("t", self._multi_snapshot(), "later_kev_90d")
        assert len(run.population) == 2
        assert run.population == {"CVE-A@2025-09-01", "CVE-A@2026-01-01"}

    def test_labels_are_not_ord_together(self):
        """Only the second snapshot is positive; collapsing would make the CVE positive."""
        run = EvaluationRun("t", self._multi_snapshot(), "later_kev_90d")
        assert run.positives == {"CVE-A@2026-01-01"}

    def test_recall_is_not_inflated_by_the_other_snapshot(self):
        """
        EPSS-only flags the high-EPSS snapshot, which is the NON-positive one. Correct
        recall is 0. Keyed on cve_id it would read 1.0, because the CVE was both
        'flagged somewhere' and 'positive somewhere'.
        """
        run = EvaluationRun("t", self._multi_snapshot(), "later_kev_90d")
        assert run.run()["epss_only"]["recall"] == 0.0

    def test_bootstrap_clusters_by_cve_not_by_unit(self):
        run = EvaluationRun("t", self._multi_snapshot(), "later_kev_90d")
        run.run()
        ci = run.confidence_intervals(n_resamples=50)["epss_only"]["workload_reduction"]
        assert ci["n_units"] == 2      # two predictions
        assert ci["n_clusters"] == 1   # but one independent CVE

    def test_records_without_a_snapshot_fall_back_to_cve_id(self):
        run = EvaluationRun("t", records(5, ("CVE-0",)), "later_kev_90d")
        assert "CVE-0" in run.population
        assert "@" not in "".join(run.population)
