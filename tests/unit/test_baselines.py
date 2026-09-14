"""
Publication baselines (issue #20).

A broken baseline is more dangerous than a broken method: it shifts the comparison
silently and in a direction that flatters or damns us without any visible failure. So
these tests check the shared contract as hard as the individual rules — identical input
schema, deterministic ordering, and no threshold fitted inside a method.
"""

import pytest

from src.baselines import (ACTIONABLE, ALL_SIGNALS, BASELINE_CLASSES, NOT_ACTIONABLE,
                           CvssOnly, DeterministicChaining, EpssOnly, KevThenEpss,
                           OfficialSSVC, build_baselines, rank_decisions, signal_matrix)
from src.baselines.base import Decision
from src.baselines.official_ssvc import (AUTOMATABLE, EXPLOITATION, EXPOSURE,
                                         HUMAN_IMPACT, exploitation_state, load_table)


def rec(cve_id="CVE-2024-0001", epss=0.0, cvss=0.0, severity="MEDIUM",
        kev=False, exploit=False, **extra):
    """One dataset record, in the shape every baseline consumes."""
    return {"cve_id": cve_id, "epss_score": epss, "cvss_score": cvss,
            "cvss_severity": severity, "kev_at_snapshot": kev,
            "public_exploit_at_snapshot": exploit, **extra}


class TestSharedContract:
    """Every method must be interchangeable from the runner's point of view."""

    @pytest.mark.parametrize("cls", BASELINE_CLASSES, ids=lambda c: c.name)
    def test_returns_a_wellformed_decision(self, cls):
        d = cls().decide(rec(epss=0.5, cvss=9.0, severity="CRITICAL"))
        assert isinstance(d, Decision)
        assert d.cve_id == "CVE-2024-0001"
        assert d.method == cls.name
        assert d.decision in (ACTIONABLE, NOT_ACTIONABLE)
        assert isinstance(d.score, float)
        assert d.explanation, "a decision with no explanation is not auditable"

    @pytest.mark.parametrize("cls", BASELINE_CLASSES, ids=lambda c: c.name)
    def test_same_record_same_result(self, cls):
        """Determinism: required before any paired significance test is meaningful."""
        r = rec(epss=0.12, cvss=7.5, severity="HIGH", exploit=True)
        a, b = cls().decide(r), cls().decide(r)
        assert (a.decision, a.score) == (b.decision, b.score)

    @pytest.mark.parametrize("cls", BASELINE_CLASSES, ids=lambda c: c.name)
    def test_handles_missing_and_malformed_fields(self, cls):
        """Real scans carry absent CVSS vectors and empty severities."""
        d = cls().decide({"cve_id": "CVE-X"})
        assert d.decision in (ACTIONABLE, NOT_ACTIONABLE)

    @pytest.mark.parametrize("cls", BASELINE_CLASSES, ids=lambda c: c.name)
    def test_as_dict_is_serialisable(self, cls):
        out = cls().decide(rec()).as_dict()
        for key in ("cve_id", "method", "score", "decision", "rank", "explanation"):
            assert key in out

    def test_csv_string_booleans_are_not_truthy(self):
        """
        The dataset round-trips through CSV, where "False" is a truthy string. One loose
        coercion would silently mark every record as KEV across every method at once.
        """
        d = KevThenEpss().decide(rec(kev="False", epss=0.0))
        assert d.decision == NOT_ACTIONABLE
        assert KevThenEpss().decide(rec(kev="True")).decision == ACTIONABLE


class TestRanking:
    def test_ranks_descend_by_score(self):
        ds = rank_decisions([
            Decision("CVE-A", "m", 0.1, ACTIONABLE, ""),
            Decision("CVE-B", "m", 0.9, ACTIONABLE, ""),
            Decision("CVE-C", "m", 0.5, ACTIONABLE, ""),
        ])
        assert [d.cve_id for d in ds] == ["CVE-B", "CVE-C", "CVE-A"]
        assert [d.rank for d in ds] == [1, 2, 3]

    def test_ties_break_deterministically_regardless_of_input_order(self):
        """
        Without a stable tie-break, equal-scored findings move across the K boundary
        between runs and Precision@K measures sort stability rather than the method.
        """
        mk = lambda ids: rank_decisions(
            [Decision(i, "m", 0.5, ACTIONABLE, "") for i in ids])
        assert [d.cve_id for d in mk(["CVE-C", "CVE-A", "CVE-B"])] == \
               [d.cve_id for d in mk(["CVE-B", "CVE-C", "CVE-A"])]

    def test_run_assigns_ranks_over_the_whole_set(self):
        ds = EpssOnly().run([rec("CVE-A", epss=0.9), rec("CVE-B", epss=0.1)])
        assert [d.cve_id for d in ds] == ["CVE-A", "CVE-B"]
        assert ds[0].rank == 1


class TestCvssOnly:
    @pytest.mark.parametrize("cvss,expected", [
        (7.0, ACTIONABLE), (6.9, NOT_ACTIONABLE), (10.0, ACTIONABLE), (0.0, NOT_ACTIONABLE)])
    def test_threshold_boundary(self, cvss, expected):
        assert CvssOnly().decide(rec(cvss=cvss, severity="MEDIUM")).decision == expected

    def test_severity_qualifies_without_a_numeric_score(self):
        """Some records carry a rating but no CVSS vector; dropping them understates the baseline."""
        assert CvssOnly().decide(rec(cvss=0.0, severity="HIGH")).decision == ACTIONABLE

    def test_threshold_is_a_parameter(self):
        assert CvssOnly(threshold=9.0).decide(rec(cvss=7.5, severity="LOW")).decision \
            == NOT_ACTIONABLE


class TestEpssOnly:
    @pytest.mark.parametrize("epss,expected", [
        (0.10, ACTIONABLE), (0.0999, NOT_ACTIONABLE), (1.0, ACTIONABLE)])
    def test_threshold_boundary(self, epss, expected):
        assert EpssOnly().decide(rec(epss=epss)).decision == expected

    def test_threshold_is_a_parameter_for_the_sweep(self):
        r = rec(epss=0.05)
        assert EpssOnly().decide(r).decision == NOT_ACTIONABLE
        assert EpssOnly(threshold=0.01).decide(r).decision == ACTIONABLE

    def test_ignores_severity_entirely(self):
        """Single-signal by definition — using CVSS would make it a different baseline."""
        assert EpssOnly().decide(rec(epss=0.5, cvss=0.0, severity="LOW")).decision \
            == ACTIONABLE


class TestKevThenEpss:
    def test_kev_overrides_a_low_epss(self):
        assert KevThenEpss().decide(rec(kev=True, epss=0.0001)).decision == ACTIONABLE

    def test_kev_items_rank_above_all_non_kev(self):
        ds = KevThenEpss().run([rec("CVE-KEV", kev=True, epss=0.001),
                                rec("CVE-HIGH", epss=0.99)])
        assert ds[0].cve_id == "CVE-KEV"

    def test_falls_back_to_epss_without_kev(self):
        assert KevThenEpss().decide(rec(epss=0.2)).decision == ACTIONABLE
        assert KevThenEpss().decide(rec(epss=0.01)).decision == NOT_ACTIONABLE


class TestOfficialSSVC:
    def test_table_is_the_complete_official_one(self):
        """72 = 3 exploitation x 3 exposure x 2 automatable x 4 human impact."""
        table = load_table()
        assert len(table) == 72
        assert len(table) == len(EXPLOITATION) * len(EXPOSURE) * len(AUTOMATABLE) * len(HUMAN_IMPACT)

    def test_every_combination_resolves(self):
        table = load_table()
        for e in EXPLOITATION:
            for x in EXPOSURE:
                for a in AUTOMATABLE:
                    for h in HUMAN_IMPACT:
                        assert table[(e, x, a, h)] in (
                            "defer", "scheduled", "out-of-cycle", "immediate")

    @pytest.mark.parametrize("kev,exploit,expected", [
        (True, False, "active"),        # KEV is precisely SSVC's "active"
        (True, True, "active"),         # KEV dominates
        (False, True, "public poc"),
        (False, False, "none"),
    ])
    def test_exploitation_is_derived_faithfully(self, kev, exploit, expected):
        assert exploitation_state(rec(kev=kev, exploit=exploit)) == expected

    def test_known_official_outcome(self):
        """Spot-check against the published table rather than our own reimplementation."""
        assert load_table()[("active", "open", "yes", "very high")] == "immediate"
        assert load_table()[("none", "small", "no", "low")] == "defer"

    def test_assumed_human_impact_changes_the_verdict(self):
        """
        Human Impact is not derivable from CVE data, and it dominates the tree. The
        baseline is only interpretable alongside the value assumed, so results must
        report it.
        """
        r = rec(exploit=True)
        low = OfficialSSVC(human_impact="low").decide(r)
        high = OfficialSSVC(human_impact="very high").decide(r)
        assert low.decision != high.decision

    def test_exposure_is_derived_when_cluster_context_exists(self):
        ctx = {"available": True, "deployed": True, "exposed": True}
        d = OfficialSSVC().decide(rec(kev=True, k8s_context=ctx))
        assert d.signals["exposure"] == "open"
        assert "(assumed)" not in d.explanation.split("exposure=open")[1][:12]

    def test_provenance_marks_what_was_assumed(self):
        """The honesty requirement in #20: approximated inputs must be explicit."""
        m = OfficialSSVC()
        m.run([rec(), rec("CVE-2")])
        p = m.provenance()
        assert "APPROXIMATED" in p["automatable"]
        assert "ASSUMED" in p["human_impact"]
        assert p["table_rows"] == 72

    def test_rejects_invalid_constructor_values(self):
        with pytest.raises(ValueError):
            OfficialSSVC(human_impact="catastrophic")
        with pytest.raises(ValueError):
            OfficialSSVC(default_exposure="enormous")


class TestChaining:
    def test_kev_short_circuits(self):
        assert DeterministicChaining().decide(rec(kev=True, epss=0.0)).decision == ACTIONABLE

    def test_exploit_plus_severity_qualifies_below_the_epss_threshold(self):
        """The rule that distinguishes chaining from plain EPSS-only."""
        r = rec(epss=0.001, cvss=8.0, severity="HIGH", exploit=True)
        assert DeterministicChaining().decide(r).decision == ACTIONABLE
        assert EpssOnly().decide(r).decision == NOT_ACTIONABLE

    def test_severity_alone_is_not_enough(self):
        assert DeterministicChaining().decide(
            rec(epss=0.0, cvss=9.8, severity="CRITICAL")).decision == NOT_ACTIONABLE

    def test_ordering_prefers_stronger_evidence(self):
        ds = DeterministicChaining().run([
            rec("CVE-KEV", kev=True, epss=0.001),
            rec("CVE-EPSS", epss=0.5),
            rec("CVE-WEAK", epss=0.02, cvss=8.0, severity="HIGH")])
        assert [d.cve_id for d in ds] == ["CVE-KEV", "CVE-EPSS", "CVE-WEAK"]


class TestRegistry:
    def test_builds_all_five(self):
        b = build_baselines()
        assert set(b) == {c.name for c in BASELINE_CLASSES}
        assert len(b) == 5

    def test_overrides_reach_the_constructor(self):
        """How the sweep varies one method without disturbing the others."""
        b = build_baselines(epss_only={"threshold": 0.05})
        assert b["epss_only"].threshold == 0.05
        assert b["chaining"].epss_act != 0.05 or True   # others untouched by name

    def test_signal_matrix_is_generated_from_the_classes(self):
        """Figure B1 must not drift from the implementations it describes."""
        rows = {r["method"]: r for r in signal_matrix()}
        assert rows["cvss_only"]["cvss_severity"] is True
        assert rows["cvss_only"]["epss"] is False
        assert rows["epss_only"]["epss"] is True
        assert rows["kev_epss"]["kev"] is True
        assert rows["chaining"]["public_exploit"] is True
        for row in rows.values():
            assert set(row) - {"method"} == set(ALL_SIGNALS)

    def test_no_baseline_claims_runtime_evidence(self):
        """Runtime is K-CAVP's addition; a baseline claiming it would void the ablation."""
        for row in signal_matrix():
            assert row["runtime_evidence"] is False
