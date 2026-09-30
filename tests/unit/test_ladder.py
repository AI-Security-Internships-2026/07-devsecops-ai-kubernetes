"""
Progressive noise-reduction ladder (issue #26).

The ladder's whole value is that each rung differs from the one below it by *exactly one*
signal. If that containment breaks, the marginal effect attributed to a layer is really
the effect of two layers, and the table in the paper becomes wrong in a way no reader
could detect. So these tests check the structure of the ladder as hard as the numbers.

The inert rungs are tested too. L4, L6 and L7 are expected to be flat on CVE-level data,
and the danger is that a future change makes one of them move without anyone noticing
that the paper still describes it as structurally unmeasurable.
"""

import pytest

from src.baselines.base import ACTIONABLE, NOT_ACTIONABLE
from src.baselines.scan_only import ScanOnly
from src.evaluation import ladder as L


def rec(cve_id="CVE-2024-0001", epss=0.0, cvss=0.0, severity="MEDIUM",
        kev=False, exploit=False, **extra):
    return {"cve_id": cve_id, "epss_score": epss, "cvss_score": cvss,
            "cvss_severity": severity, "kev_at_snapshot": kev,
            "public_exploit_at_snapshot": exploit, **extra}


class TestScanOnly:
    """L0 is the denominator: it must flag everything, unconditionally."""

    @pytest.mark.parametrize("record", [
        rec(),
        rec(epss=0.99, cvss=10.0, severity="CRITICAL", kev=True),
        rec(epss=0.0, cvss=0.0, severity=""),
    ])
    def test_everything_is_actionable(self, record):
        assert ScanOnly().decide(record).decision == ACTIONABLE

    def test_reduction_against_l0_is_zero(self):
        records = [rec(f"CVE-2024-{i:04d}", epss=i / 100) for i in range(50)]
        decisions = ScanOnly().run(records)
        assert sum(1 for d in decisions if d.decision == NOT_ACTIONABLE) == 0

    def test_ranking_carries_no_signal(self):
        """
        Constant score is deliberate. If a future edit ranked L0 by CVSS it would look
        like unprioritized output has useful ordering, which it does not.
        """
        records = [rec(f"CVE-2024-{i:04d}", cvss=10.0 - i) for i in range(5)]
        assert {d.score for d in ScanOnly().run(records)} == {0.0}


class TestLadderStructure:

    def test_every_rung_has_a_method(self):
        methods = L.build_ladder()
        assert set(methods) == {r.key for r in L.RUNGS}

    def test_rungs_are_ordered_and_unique(self):
        keys = [r.key for r in L.RUNGS]
        assert keys == sorted(keys), "rung ids must read in ladder order"
        assert len(keys) == len(set(keys))

    def test_every_rung_but_the_first_names_its_comparison(self):
        for rung in L.RUNGS:
            if rung.key == "L0":
                assert rung.compare_to is None
            else:
                assert rung.compare_to, f"{rung.key} has no comparison point"

    def test_comparison_targets_exist(self):
        keys = {r.key for r in L.RUNGS}
        for rung in L.RUNGS:
            if rung.compare_to:
                assert rung.compare_to in keys

    def test_cumulative_rungs_compare_to_the_rung_below(self):
        """A cumulative rung's delta is only interpretable against its predecessor."""
        keys = [r.key for r in L.RUNGS]
        for rung in L.RUNGS:
            if rung.cumulative and rung.key != "L3":
                assert rung.compare_to == keys[keys.index(rung.key) - 1]

    def test_single_signal_rungs_compare_to_the_untriaged_queue(self):
        for rung in L.RUNGS:
            if not rung.cumulative and rung.key != "L0":
                assert rung.compare_to == "L0"

    def test_collapsed_stages_are_all_real_rungs(self):
        keys = {r.key for r in L.RUNGS}
        assert set(L.COLLAPSED_STAGES) <= keys


class TestLayerContainment:
    """
    Each cumulative rung must flag a superset of the rung below it.

    Upward refinements only add findings to the queue, so containment is the property
    that makes 'this layer contributed N findings' a true statement rather than a net
    figure hiding movement in both directions.
    """

    RECORDS = [
        rec(f"CVE-2024-{i:04d}", epss=i / 200, cvss=4.0 + (i % 7),
            severity=["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
            exploit=(i % 3 == 0))
        for i in range(400)
    ]

    def flagged(self, key):
        method = L.build_ladder()[key]
        return {d.cve_id for d in method.run(self.RECORDS)
                if d.decision == ACTIONABLE}

    @pytest.mark.parametrize("lower,upper", [("L3", "L4"), ("L4", "L5"),
                                             ("L5", "L6"), ("L6", "L7")])
    def test_each_rung_contains_the_one_below(self, lower, upper):
        assert self.flagged(lower) <= self.flagged(upper)

    def test_the_exploit_rung_actually_adds_findings(self):
        """
        L5 is the only rung that can move on CVE-level data. If it stops moving, the
        ladder has nothing to show between the fused base and Dataset B, and the paper
        section needs rewriting rather than silently reporting a flat table.
        """
        assert self.flagged("L5") > self.flagged("L4")


class TestInertRungs:
    """
    L4/L6/L7 are documented as unable to move on CVE-level records. These tests pin that
    documentation to behaviour so it cannot quietly become false.
    """

    RECORDS = [rec(f"CVE-2024-{i:04d}", epss=i / 300, cvss=5.0 + (i % 5),
                   severity="HIGH", exploit=(i % 2 == 0)) for i in range(300)]

    def flagged(self, key):
        return {d.cve_id for d in L.build_ladder()[key].run(self.RECORDS)
                if d.decision == ACTIONABLE}

    def test_kev_rung_is_flat_when_no_row_is_in_kev(self):
        assert self.flagged("L4") == self.flagged("L3")

    def test_kev_rung_moves_once_a_row_is_in_kev(self):
        """The rung is inert because of the data, not because the code ignores KEV."""
        records = self.RECORDS + [rec("CVE-2024-9999", epss=0.0, cvss=1.0,
                                      severity="LOW", kev=True)]
        ladder = L.build_ladder()
        l3 = {d.cve_id for d in ladder["L3"].run(records) if d.decision == ACTIONABLE}
        l4 = {d.cve_id for d in ladder["L4"].run(records) if d.decision == ACTIONABLE}
        assert "CVE-2024-9999" not in l3
        assert "CVE-2024-9999" in l4

    def test_context_and_runtime_rungs_are_flat_without_those_columns(self):
        assert self.flagged("L6") == self.flagged("L5")
        assert self.flagged("L7") == self.flagged("L6")

    def test_context_rung_moves_once_context_is_present(self):
        records = [rec("CVE-2024-1000", epss=0.5, cvss=9.0, severity="CRITICAL",
                       k8s_context={"available": True, "deployed": False})]
        ladder = L.build_ladder()
        l5 = ladder["L5"].run(records)[0]
        l6 = ladder["L6"].run(records)[0]
        assert l5.decision == ACTIONABLE
        assert l6.decision == NOT_ACTIONABLE, "not-deployed must de-escalate at L6"


class TestLadderRows:

    SUMMARY = {
        "L0": {"actionable": 1000, "workload_reduction": 0.0, "recall": 1.0},
        "L1": {"actionable": 500, "workload_reduction": 0.5, "recall": 0.9},
        "L2": {"actionable": 100, "workload_reduction": 0.9, "recall": 0.4},
        "L3": {"actionable": 200, "workload_reduction": 0.8, "recall": 0.5},
        "L4": {"actionable": 200, "workload_reduction": 0.8, "recall": 0.5},
        "L5": {"actionable": 220, "workload_reduction": 0.78, "recall": 0.52},
        "L6": {"actionable": 220, "workload_reduction": 0.78, "recall": 0.52},
        "L7": {"actionable": 220, "workload_reduction": 0.78, "recall": 0.52},
    }

    def rows(self):
        return L.ladder_rows(self.SUMMARY)

    def test_first_rung_has_no_deltas(self):
        first = self.rows()[0]
        assert first["rung"] == "L0"
        assert first["delta_actionable"] is None

    def test_delta_is_computed_against_the_named_rung(self):
        by_key = {r["rung"]: r for r in self.rows()}
        assert by_key["L3"]["compare_to"] == "L0"
        assert by_key["L3"]["delta_actionable"] == 200 - 1000
        assert by_key["L5"]["compare_to"] == "L4"
        assert by_key["L5"]["delta_actionable"] == 20

    def test_a_rung_that_grows_the_queue_reports_a_positive_delta(self):
        """
        Threat-intelligence layers escalate, so they enlarge the queue. The ladder must
        show that rather than presenting every step as a reduction.
        """
        by_key = {r["rung"]: r for r in self.rows()}
        assert by_key["L5"]["delta_actionable"] > 0
        assert by_key["L5"]["delta_recall"] == pytest.approx(0.02)

    def test_missing_rung_is_skipped_not_faked(self):
        partial = {k: v for k, v in self.SUMMARY.items() if k != "L7"}
        assert "L7" not in {r["rung"] for r in L.ladder_rows(partial)}

    def test_collapsed_view_chains_through_the_five_stages(self):
        collapsed = L.collapsed_rows(self.rows())
        assert [r["rung"] for r in collapsed] == list(L.COLLAPSED_STAGES)
        assert collapsed[0]["delta_actionable"] is None
        assert collapsed[1]["delta_actionable"] == 200 - 1000
        # L5 against L3, not against L4, because the collapsed view skips L4.
        assert collapsed[2]["compare_to"] == "L3"
        assert collapsed[2]["delta_actionable"] == 20

    def test_documented_inert_rungs_are_reported_as_such(self):
        statuses = {r["rung"]: r["status"] for r in L.inert_rungs(self.rows())}
        assert statuses["L4"] == "inert as documented"
        assert statuses["L6"] == "inert as documented"
        assert statuses["L7"] == "inert as documented"

    def test_an_undocumented_flat_rung_is_flagged(self):
        summary = dict(self.SUMMARY)
        summary["L5"] = dict(summary["L4"])          # L5 stops moving
        statuses = {r["rung"]: r["status"] for r in L.inert_rungs(L.ladder_rows(summary))}
        assert statuses["L5"] == "unexpectedly flat"

    def test_an_inert_rung_that_moves_is_flagged(self):
        summary = dict(self.SUMMARY)
        summary["L4"] = {"actionable": 250, "workload_reduction": 0.75, "recall": 0.6}
        statuses = {r["rung"]: r["status"] for r in L.inert_rungs(L.ladder_rows(summary))}
        assert statuses["L4"] == "expected inert but moved"
