"""
Threshold configuration and the experiments it has to support.

Two reviewer requirements meet here. Thresholds must be centralized and documented
with their provenance (issues #19, #26), and the sensitivity sweep and bound-strategy
comparison must vary them without editing source (issue #24, experiments 6B and 6D).
So these tests check both the metadata and that varying a threshold actually changes
the decision it governs — a config that is read but ignored would pass a naive test.
"""

import pytest

from src.triage.ssvc import _cap_total_escalation, analyze, apply_context, classify_priority
from src.triage.thresholds import (
    DEFAULTS,
    FALCO_CRITICAL_TIER,
    LADDER,
    PROVENANCE,
    Thresholds,
    provenance_rows,
)
from tests.conftest import alert, context, cve, runtime


class TestConfigMechanics:
    def test_defaults_match_the_documented_values(self):
        """These are the numbers the paper quotes; drift here silently invalidates it."""
        assert DEFAULTS.epss_act == 0.10
        assert DEFAULTS.epss_attend == 0.01
        assert DEFAULTS.cvss_high == 7.0
        assert DEFAULTS.epss_context_escalate == 0.05
        assert DEFAULTS.epss_context_deescalate == 0.20
        assert DEFAULTS.max_escalation_levels == 1

    def test_is_immutable(self):
        """A threshold set is a value; a run must not be able to mutate the one it got."""
        with pytest.raises(Exception):
            DEFAULTS.epss_act = 0.5

    def test_replace_returns_a_new_set(self):
        variant = DEFAULTS.replace(epss_act=0.05)
        assert variant.epss_act == 0.05
        assert DEFAULTS.epss_act == 0.10       # original untouched
        assert variant.epss_attend == DEFAULTS.epss_attend

    def test_replace_rejects_unknown_names(self):
        """A typo in a sweep config must fail loudly, not silently do nothing."""
        with pytest.raises(ValueError, match="unknown threshold"):
            DEFAULTS.replace(epss_actt=0.05)

    def test_from_env_reads_overrides(self):
        t = Thresholds.from_env({"K_CAVP_EPSS_ACT": "0.05",
                                 "K_CAVP_MAX_ESCALATION_LEVELS": "2"})
        assert t.epss_act == 0.05
        assert t.max_escalation_levels == 2
        assert t.cvss_high == DEFAULTS.cvss_high    # unset fields keep defaults

    def test_from_env_ignores_blank(self):
        assert Thresholds.from_env({"K_CAVP_EPSS_ACT": "  "}).epss_act == DEFAULTS.epss_act

    def test_from_env_rejects_malformed(self):
        """
        Silently falling back would label results with a threshold never applied,
        which is worse than crashing.
        """
        with pytest.raises(ValueError, match="not a valid"):
            Thresholds.from_env({"K_CAVP_EPSS_ACT": "high"})

    def test_as_dict_round_trips(self):
        assert Thresholds(**DEFAULTS.as_dict()) == DEFAULTS


class TestProvenance:
    def test_every_threshold_has_provenance(self):
        """A threshold with no recorded basis cannot appear in the paper."""
        assert set(PROVENANCE) == set(DEFAULTS.as_dict())

    def test_basis_is_one_of_two_values(self):
        for name, meta in PROVENANCE.items():
            assert meta["basis"] in ("published", "internal"), name

    def test_published_thresholds_cite_a_source(self):
        for name, meta in PROVENANCE.items():
            if meta["basis"] == "published":
                assert meta["source"], f"{name} is marked published but cites nothing"

    def test_internal_thresholds_do_not_claim_a_source(self):
        """Overstating provenance is the specific failure the reviewer asked about."""
        for name, meta in PROVENANCE.items():
            if meta["basis"] == "internal":
                assert meta["source"] is None, f"{name} is ours but names a source"

    def test_the_actionable_boundary_is_citable(self):
        """
        The two thresholds shared with the baselines must be defensible by citation,
        since they are what makes the comparison fair by construction.
        """
        assert PROVENANCE["epss_act"]["basis"] == "published"
        assert PROVENANCE["cvss_high"]["basis"] == "published"

    def test_rows_are_published_first(self):
        bases = [r["basis"] for r in provenance_rows()]
        assert bases == sorted(bases, key=lambda b: b != "published")

    def test_rows_carry_a_usable_source_string(self):
        for r in provenance_rows():
            assert r["source"]              # "this work" for internal ones
            assert r["note"]


class TestThresholdsActuallyGovernDecisions:
    """A config that is read but not applied would pass metadata tests alone."""

    @pytest.mark.parametrize("epss_act,expected", [
        (0.01, "CRITICAL"),   # 0.06 is above the cut
        (0.05, "CRITICAL"),
        (0.10, "MEDIUM"),     # 0.06 now below it
        (0.20, "MEDIUM"),
    ])
    def test_epss_act_moves_the_act_boundary(self, epss_act, expected):
        finding = cve(epss=0.06, cvss=5.0, severity="MEDIUM")
        got, _ = classify_priority(finding, in_kev=False,
                                   thresholds=DEFAULTS.replace(epss_act=epss_act))
        assert got == expected

    def test_cvss_high_moves_the_attend_boundary(self):
        finding = cve(epss=0.02, cvss=6.0, severity="MEDIUM")
        assert classify_priority(finding, in_kev=False)[0] == "MEDIUM"
        assert classify_priority(
            finding, in_kev=False,
            thresholds=DEFAULTS.replace(cvss_high=5.0))[0] == "HIGH"

    def test_context_escalate_threshold_is_respected(self):
        finding = cve(epss=0.03)
        assert apply_context("HIGH", finding, context(exposed=True))[0] == "HIGH"
        assert apply_context("HIGH", finding, context(exposed=True),
                             DEFAULTS.replace(epss_context_escalate=0.02))[0] == "CRITICAL"

    def test_context_deescalate_threshold_is_respected(self):
        finding = cve(epss=0.30)
        assert apply_context("CRITICAL", finding, context())[0] == "CRITICAL"
        assert apply_context("CRITICAL", finding, context(),
                             DEFAULTS.replace(epss_context_deescalate=0.5))[0] == "HIGH"


class TestBoundStrategies:
    """
    Experiment 6B compares no-refinement / +1 / +2 / unbounded. The reviewer's point
    stands: the default bound has to be justified by results, not by the defects that
    prompted it, and that requires the alternatives to be runnable.
    """

    @pytest.mark.parametrize("levels,expected", [
        (0, "MEDIUM"),      # no upward refinement at all
        (1, "HIGH"),        # default
        (2, "CRITICAL"),    # exploit +1 then runtime +1
        (-1, "CRITICAL"),   # unbounded
    ])
    def test_all_four_strategies_are_selectable(self, levels, expected):
        finding = cve(epss=0.02, cvss=5.0, severity="MEDIUM", packages=["coreutils"])
        assert classify_priority(finding, in_kev=False)[0] == "MEDIUM"
        result = analyze(
            finding, in_kev=False, exploit_exists=True,
            runtime=runtime(max_priority="Critical",
                            alerts=[alert(packages=["coreutils"])]),
            thresholds=DEFAULTS.replace(max_escalation_levels=levels),
        )
        assert result["priority"] == expected

    def test_cap_note_reports_the_allowance_in_force(self):
        _, note = _cap_total_escalation("LOW", "CRITICAL",
                                        DEFAULTS.replace(max_escalation_levels=2))
        assert note and "2 levels" in note

    def test_zero_levels_note_reads_correctly(self):
        _, note = _cap_total_escalation("MEDIUM", "CRITICAL",
                                        DEFAULTS.replace(max_escalation_levels=0))
        assert note and "may not be raised above" in note

    def test_ceiling_cannot_exceed_the_ladder(self):
        """A generous bound must not index past CRITICAL."""
        got, _ = _cap_total_escalation("HIGH", "CRITICAL",
                                       DEFAULTS.replace(max_escalation_levels=5))
        assert got == "CRITICAL"

    def test_deescalation_is_unaffected_by_the_bound(self):
        for levels in (0, 1, 2, -1):
            got, _ = _cap_total_escalation("CRITICAL", "LOW",
                                           DEFAULTS.replace(max_escalation_levels=levels))
            assert got == "LOW"


class TestSharedDefinitions:
    def test_ladder_matches_the_decision_engine(self):
        from src.triage.ssvc import _LADDER
        assert list(LADDER) == list(_LADDER)

    def test_falco_tier_is_shared_not_duplicated(self):
        from src.triage.ssvc import _FALCO_CRITICAL_TIER
        assert _FALCO_CRITICAL_TIER is FALCO_CRITICAL_TIER
