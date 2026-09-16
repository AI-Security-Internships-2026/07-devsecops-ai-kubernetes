"""
Evaluation metrics, CIs and significance tests (issue #22).

These functions produce the numbers that go in the paper, so the tests check them
against cases whose answers can be worked out by hand rather than against the
implementation's own output. Three properties matter most:

  * clustered resampling must WIDEN intervals when rows are correlated,
  * McNemar must use the exact test at the small discordant counts this data produces,
  * precision must be reported as a lower bound, since non-positives are unknown.
"""

import math

import pytest

from src.evaluation import metrics as M


class TestClassification:
    def test_hand_checkable_case(self):
        pop = {f"C{i}" for i in range(100)}
        pos = {"C1", "C2", "C3", "C4"}
        flagged = {"C1", "C2", "C50", "C51"}
        m = M.classification_metrics(flagged, pos, pop)
        assert m["tp"] == 2
        assert m["fn"] == 2
        assert m["recall"] == 0.5
        assert m["precision_lower_bound"] == 0.5
        assert m["workload_reduction"] == pytest.approx(0.96)

    def test_coverage_and_efficiency_alias_the_same_numbers(self):
        """
        The EPSS literature says coverage/efficiency; we also say recall/precision.
        Emitting both keeps our figures comparable to published work without
        recomputing them differently.
        """
        m = M.classification_metrics({"A"}, {"A", "B"}, {"A", "B", "C"})
        assert m["coverage"] == m["recall"]
        assert m["efficiency"] == m["precision_lower_bound"]

    def test_flagging_nothing_gives_zero_recall_not_an_error(self):
        m = M.classification_metrics(set(), {"A"}, {"A", "B"})
        assert m["recall"] == 0.0
        assert m["precision_lower_bound"] is None      # undefined, not zero
        assert m["workload_reduction"] == 1.0

    def test_no_positives_leaves_recall_undefined(self):
        """An image with no confirmed-exploited CVEs cannot score recall."""
        m = M.classification_metrics({"A"}, set(), {"A", "B"})
        assert m["recall"] is None

    def test_flagging_everything_gives_full_recall_and_no_reduction(self):
        pop = {"A", "B", "C"}
        m = M.classification_metrics(pop, {"A"}, pop)
        assert m["recall"] == 1.0
        assert m["workload_reduction"] == 0.0

    def test_unconfirmed_counts_are_named_honestly(self):
        """
        Non-positives are unknown, not negative. The field names have to carry that or
        the paper will report them as false positives.
        """
        m = M.classification_metrics({"A", "B"}, {"A"}, {"A", "B", "C"})
        assert "fp_unconfirmed" in m and "tn_unconfirmed" in m
        assert "fp" not in m and "tn" not in m


class TestRanking:
    def test_precision_and_recall_at_k(self):
        ranked = ["C1", "C9", "C2", "C8", "C3"]
        pos = {"C1", "C2", "C3", "C4"}
        assert M.precision_at_k(ranked, pos, 2) == 0.5
        assert M.recall_at_k(ranked, pos, 5) == 0.75

    def test_k_larger_than_the_list_uses_what_exists(self):
        assert M.precision_at_k(["A", "B"], {"A"}, 100) == 0.5

    def test_perfect_ranking_scores_one(self):
        pos = {"A", "B"}
        assert M.ndcg_at_k(["A", "B", "C"], pos, 3) == pytest.approx(1.0)

    def test_ndcg_rewards_putting_positives_first(self):
        pos = {"A"}
        assert M.ndcg_at_k(["A", "B", "C"], pos, 3) > M.ndcg_at_k(["B", "C", "A"], pos, 3)

    def test_no_positives_is_zero_not_a_crash(self):
        assert M.ndcg_at_k(["A"], set(), 5) == 0.0
        assert M.recall_at_k(["A"], set(), 5) == 0.0

    def test_bundle_covers_every_k(self):
        out = M.ranking_metrics(["A", "B"], {"A"}, ks=(1, 2))
        for k in (1, 2):
            for metric in ("precision_at_", "recall_at_", "ndcg_at_"):
                assert f"{metric}{k}" in out


class TestClusteredBootstrap:
    def _rows(self, n_cves, per_cve):
        return [{"cve": f"C{i}", "v": i % 2}
                for i in range(n_cves) for _ in range(per_cve)]

    @staticmethod
    def _mean(sample):
        return sum(r["v"] for r in sample) / len(sample) if sample else None

    def test_correlated_rows_widen_the_interval(self):
        """
        The property the whole design rests on. 100 CVEs x3 rows carries the same row
        count as 300 independent CVEs but a third of the information, so its interval
        must be wider. Resampling rows instead of clusters would make them equal — and
        would silently understate every confidence interval in the paper.
        """
        ind = M.clustered_bootstrap_ci(self._rows(300, 1), self._mean,
                                       lambda r: r["cve"], n_resamples=400)
        dup = M.clustered_bootstrap_ci(self._rows(100, 3), self._mean,
                                       lambda r: r["cve"], n_resamples=400)
        assert ind["n_clusters"] == 300 and dup["n_clusters"] == 100
        assert (dup["upper"] - dup["lower"]) > (ind["upper"] - ind["lower"])

    def test_interval_brackets_the_point_estimate(self):
        rows = self._rows(100, 2)
        ci = M.clustered_bootstrap_ci(rows, self._mean, lambda r: r["cve"], n_resamples=300)
        assert ci["lower"] <= ci["point"] <= ci["upper"]

    def test_is_seeded_and_repeatable(self):
        """A CI that moves between runs of the same analysis is not reportable."""
        rows = self._rows(50, 2)
        a = M.clustered_bootstrap_ci(rows, self._mean, lambda r: r["cve"], n_resamples=200)
        b = M.clustered_bootstrap_ci(rows, self._mean, lambda r: r["cve"], n_resamples=200)
        assert (a["lower"], a["upper"]) == (b["lower"], b["upper"])

    def test_records_the_resampling_unit(self):
        """#22 requires the unit to be documented, not inferred by the reader."""
        ci = M.clustered_bootstrap_ci(self._rows(10, 1), self._mean,
                                      lambda r: r["cve"], n_resamples=50)
        assert "cluster" in ci["resampling_unit"]

    def test_empty_input_is_not_an_error(self):
        ci = M.clustered_bootstrap_ci([], self._mean, lambda r: r["cve"])
        assert ci["point"] is None and ci["n_clusters"] == 0


class TestMcNemar:
    def test_uses_the_exact_test_at_small_discordant_counts(self):
        """
        With ~92 positives the discordant counts are small, and the chi-square
        approximation overstates significance there. b=8, c=0 has an exact two-sided
        p of 2/2^8.
        """
        items = {f"C{i}" for i in range(20)}
        a = {f"C{i}" for i in range(10)}
        b = {f"C{i}" for i in range(2)}
        r = M.mcnemar(a, b, items)
        assert r["b"] == 8 and r["c"] == 0
        assert r["method"] == "exact binomial"
        assert r["p_value"] == pytest.approx(2 / 2 ** 8)
        assert r["significant_at_0.05"] is True

    def test_switches_to_chi_square_when_discordant_pairs_are_many(self):
        items = {f"C{i}" for i in range(200)}
        a = {f"C{i}" for i in range(60)}
        b = {f"C{i}" for i in range(40, 100)}
        r = M.mcnemar(a, b, items, exact_threshold=25)
        assert r["discordant"] >= 25
        assert "chi-square" in r["method"]

    def test_identical_methods_are_not_significant(self):
        items = {f"C{i}" for i in range(10)}
        a = {"C1", "C2"}
        r = M.mcnemar(a, a, items)
        assert r["discordant"] == 0
        assert r["p_value"] == 1.0
        assert r["significant_at_0.05"] is False

    def test_only_discordant_pairs_count(self):
        """Agreement carries no information about which method is better."""
        items = {f"C{i}" for i in range(50)}
        both = {f"C{i}" for i in range(30)}
        r = M.mcnemar(both | {"C40"}, both | {"C41"}, items)
        assert r["b"] == 1 and r["c"] == 1

    def test_symmetric_disagreement_is_not_significant(self):
        items = {f"C{i}" for i in range(40)}
        a = {f"C{i}" for i in range(0, 8)}
        b = {f"C{i}" for i in range(8, 16)}
        assert M.mcnemar(a, b, items)["significant_at_0.05"] is False


class TestPairedBootstrap:
    def test_detects_a_real_difference(self):
        rows = [{"cve": f"C{i}", "a": 1.0, "b": 0.0} for i in range(100)]
        r = M.paired_bootstrap_diff(
            rows, lambda s: sum(x["a"] for x in s) / len(s),
            lambda s: sum(x["b"] for x in s) / len(s), lambda x: x["cve"],
            n_resamples=300)
        assert r["difference"] == pytest.approx(1.0)
        assert r["excludes_zero"] is True

    def test_no_difference_spans_zero(self):
        rows = [{"cve": f"C{i}", "a": float(i % 2), "b": float(i % 2)} for i in range(100)]
        r = M.paired_bootstrap_diff(
            rows, lambda s: sum(x["a"] for x in s) / len(s),
            lambda s: sum(x["b"] for x in s) / len(s), lambda x: x["cve"],
            n_resamples=300)
        assert r["difference"] == pytest.approx(0.0)
        assert r["excludes_zero"] is False

    def test_reports_an_effect_size_not_only_a_verdict(self):
        """#26 forbids p-values without effect sizes; the difference is the effect size."""
        rows = [{"cve": f"C{i}", "a": 0.8, "b": 0.5} for i in range(50)]
        r = M.paired_bootstrap_diff(
            rows, lambda s: sum(x["a"] for x in s) / len(s),
            lambda s: sum(x["b"] for x in s) / len(s), lambda x: x["cve"],
            n_resamples=200)
        assert r["difference"] is not None
        assert r["lower"] is not None and r["upper"] is not None


class TestAttribution:
    def test_counts_each_outcome_type(self):
        cases = [
            {"expected_package": "coreutils", "attributed_package": "coreutils"},  # tp
            {"expected_package": None, "attributed_package": None},                # tn
            {"expected_package": None, "attributed_package": "openssl"},           # fp
            {"expected_package": "libssl3", "attributed_package": None},           # fn
        ]
        m = M.attribution_metrics(cases)
        assert (m["true_attributions"], m["false_attributions"]) == (1, 1)
        assert (m["missed_attributions"], m["correct_declines"]) == (1, 1)
        assert m["attribution_precision"] == 0.5
        assert m["attribution_recall"] == 0.5

    def test_declining_to_attribute_is_correct_when_nothing_applies(self):
        """The conservative path: unattributable evidence must not be a penalty."""
        m = M.attribution_metrics([{"expected_package": None, "attributed_package": None}])
        assert m["correct_declines"] == 1
        assert m["false_attribution_rate"] == 0.0

    def test_wrong_package_is_both_a_false_and_a_missed_attribution(self):
        """Attributing to the wrong package escalates the wrong finding AND misses the right one."""
        m = M.attribution_metrics(
            [{"expected_package": "coreutils", "attributed_package": "openssl"}])
        assert m["false_attributions"] == 1
        assert m["missed_attributions"] == 1
        assert m["attribution_precision"] == 0.0

    def test_empty_case_list(self):
        m = M.attribution_metrics([])
        assert m["cases"] == 0
        assert m["attribution_precision"] is None
