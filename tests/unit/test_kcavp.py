"""
K-CAVP as a comparison method (issues #20, #23).

Wrapping our own engine in the baseline interface is what makes the comparison honest,
so these tests check that the wrapper faithfully reflects the engine rather than
re-deciding anything, and that each ablation flag actually switches its component off.
"""

import pytest

from src.baselines import ACTIONABLE, NOT_ACTIONABLE, KCAVP, build_ablation
from src.baselines.kcavp import ABLATION_VARIANTS
from src.triage.thresholds import DEFAULTS


def rec(cve_id="CVE-1", epss=0.0, cvss=0.0, severity="MEDIUM", kev=False,
        exploit=False, **extra):
    return {"cve_id": cve_id, "epss_score": epss, "cvss_score": cvss,
            "cvss_severity": severity, "kev_at_snapshot": kev,
            "public_exploit_at_snapshot": exploit, **extra}


class TestDecisionMapping:
    def test_act_and_attend_are_actionable(self):
        """Both mean an analyst looks at it — the question the baselines answer."""
        assert KCAVP().decide(rec(epss=0.5)).decision == ACTIONABLE            # Act
        assert KCAVP().decide(rec(epss=0.02, cvss=8.0,
                                  severity="HIGH")).decision == ACTIONABLE     # Attend

    def test_track_tiers_are_not_actionable(self):
        assert KCAVP().decide(rec(epss=0.0001)).decision == NOT_ACTIONABLE

    def test_preserves_the_ssvc_tier_label(self):
        """Ordinal output must not be flattened to binary in the stored results."""
        assert KCAVP().decide(rec(epss=0.5)).priority == "Act"
        assert KCAVP().decide(rec(epss=0.0001)).priority == "Track"

    def test_kev_is_always_actionable(self):
        assert KCAVP().decide(rec(kev=True, epss=0.0, severity="LOW")).decision == ACTIONABLE

    def test_ranks_act_above_attend(self):
        ds = KCAVP().run([rec("CVE-ATTEND", epss=0.02, cvss=8.0, severity="HIGH"),
                          rec("CVE-ACT", epss=0.5)])
        assert ds[0].cve_id == "CVE-ACT"

    def test_carries_the_rationale(self):
        """The recorded reason is the audit trail; an empty one is not defensible."""
        d = KCAVP().decide(rec(epss=0.02, cvss=8.0, severity="HIGH", exploit=True))
        assert d.explanation


class TestAblationFlags:
    def test_disabling_exploit_removes_its_escalation(self):
        r = rec(epss=0.02, cvss=8.0, severity="HIGH", exploit=True)
        assert KCAVP(enable_exploit=True).decide(r).priority == "Act"
        assert KCAVP(enable_exploit=False).decide(r).priority == "Attend"

    def test_disabling_context_ignores_cluster_state(self):
        """Not-deployed would normally drop this to Track."""
        ctx = {"available": True, "deployed": False}
        r = rec(epss=0.5, k8s_context=ctx)
        assert KCAVP(enable_context=True).decide(r).priority == "Track"
        assert KCAVP(enable_context=False).decide(r).priority == "Act"

    def test_disabling_runtime_ignores_alerts(self):
        runtime = {"available": True, "count": 1, "max_priority": "Critical",
                   "alerts": [{"priority": "Critical", "rule": "r",
                               "packages": ["coreutils"], "process": "cat"}]}
        r = rec(epss=0.02, cvss=8.0, severity="HIGH",
                affected_packages=["coreutils"], runtime=runtime)
        assert KCAVP(enable_runtime=True).decide(r).priority == "Act"
        assert KCAVP(enable_runtime=False).decide(r).priority == "Attend"

    def test_disabling_the_bound_allows_stacking(self):
        """
        The 'Full - Bound' variant experiment 6B compares against. With the bound off,
        exploit and runtime compound and lift a MEDIUM base two levels.
        """
        runtime = {"available": True, "count": 1, "max_priority": "Critical",
                   "alerts": [{"priority": "Critical", "rule": "r",
                               "packages": ["coreutils"], "process": "cat"}]}
        r = rec(epss=0.02, cvss=5.0, severity="MEDIUM",
                affected_packages=["coreutils"], runtime=runtime, exploit=True)
        assert KCAVP(enable_bound=True).decide(r).priority == "Attend"
        assert KCAVP(enable_bound=False).decide(r).priority == "Act"


class TestAblationSet:
    def test_builds_the_six_specified_variants(self):
        """Six exactly — the runner must not be able to invent a seventh."""
        variants = build_ablation()
        assert set(variants) == set(ABLATION_VARIANTS)
        assert len(variants) == 6

    def test_each_variant_records_its_own_name(self):
        for name, method in build_ablation().items():
            assert method.decide(rec(epss=0.5)).signals["variant"] == name

    def test_variants_share_one_threshold_set(self):
        custom = DEFAULTS.replace(epss_act=0.05)
        for method in build_ablation(thresholds=custom).values():
            assert method.thresholds.epss_act == 0.05


class TestRegistration:
    def test_is_part_of_the_comparison(self):
        from src.baselines import BASELINE_CLASSES, build_baselines
        assert KCAVP in BASELINE_CLASSES
        assert "kcavp" in build_baselines()

    def test_declares_every_signal_it_uses(self):
        from src.baselines import signal_matrix
        row = next(r for r in signal_matrix() if r["method"] == "kcavp")
        for signal in ("k8s_exposure", "runtime_evidence", "epss", "kev"):
            assert row[signal] is True

    def test_is_the_only_method_claiming_runtime(self):
        """Runtime is the proposed method's addition; a baseline claiming it voids the ablation."""
        from src.baselines import signal_matrix
        claim = [r["method"] for r in signal_matrix() if r["runtime_evidence"]]
        assert claim == ["kcavp"]


class TestFieldHandling:
    def test_reads_the_dataset_severity_field(self):
        """Historical records use cvss_severity; the engine expects severity."""
        assert KCAVP().decide(rec(epss=0.02, cvss=0.0,
                                  severity="CRITICAL")).priority == "Attend"

    def test_missing_fields_do_not_crash(self):
        assert KCAVP().decide({"cve_id": "CVE-X"}).decision == NOT_ACTIONABLE

    @pytest.mark.parametrize("value", ["True", True])
    def test_kev_accepts_csv_strings_and_bools(self, value):
        assert KCAVP().decide(rec(kev=value)).decision == ACTIONABLE
