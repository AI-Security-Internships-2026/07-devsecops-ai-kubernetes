"""
The SSVC decision core — the part of the tool the paper actually claims.

Priorities under test, in order of what a reviewer would attack first:
  1. base classification thresholds (EPSS / CVSS / KEV)
  2. KEV items are always actionable  (the 100% KEV-recall invariant)
  3. each refinement moves a finding by AT MOST ONE level
  4. the three refinements TOGETHER cannot stack  (the 17->155 regression)
  5. context is bidirectional; runtime is escalate-only
"""

import pytest

from src.triage.ssvc import (
    PRIORITY_TO_DECISION,
    analyze,
    apply_context,
    apply_exploit,
    apply_runtime,
    classify_priority,
    decision_for,
)
from tests.conftest import context, cve, runtime

LADDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def rank(priority):
    """Position on the severity ladder, so 'moved at most one level' is testable."""
    return LADDER.index(priority)


# --------------------------------------------------------------- base thresholds

class TestBaseClassification:
    @pytest.mark.parametrize("epss,cvss,severity,expected", [
        (0.10, 0.0, "LOW",    "CRITICAL"),   # EPSS at the Act threshold
        (0.50, 0.0, "LOW",    "CRITICAL"),   # well above it
        (0.05, 7.5, "HIGH",   "HIGH"),       # exploitable AND severe
        (0.05, 9.0, "LOW",    "HIGH"),       # high CVSS alone qualifies
        (0.05, 2.0, "HIGH",   "HIGH"),       # HIGH severity alone qualifies
        (0.05, 2.0, "MEDIUM", "MEDIUM"),     # exploitable but not severe
        (0.009, 9.9, "CRITICAL", "LOW"),     # severe but not exploitable
        (0.0,  0.0, "UNKNOWN", "LOW"),
    ])
    def test_thresholds(self, epss, cvss, severity, expected):
        priority, decision = classify_priority(
            cve(epss=epss, cvss=cvss, severity=severity), in_kev=False)
        assert priority == expected
        assert decision == PRIORITY_TO_DECISION[expected]

    def test_kev_is_always_critical(self):
        """
        The 100% KEV-recall claim in the paper rests on this: a known-exploited CVE
        is CRITICAL regardless of how low its EPSS or CVSS is.
        """
        priority, decision = classify_priority(
            cve(epss=0.0, cvss=0.0, severity="LOW"), in_kev=True)
        assert priority == "CRITICAL"
        assert decision == "Act"

    def test_boundary_is_inclusive(self):
        """0.1 is Act and 0.0999... is not — the paper quotes these thresholds."""
        assert classify_priority(cve(epss=0.1), in_kev=False)[0] == "CRITICAL"
        assert classify_priority(cve(epss=0.0999), in_kev=False)[0] != "CRITICAL"

    def test_decision_labels(self):
        assert decision_for("CRITICAL") == "Act"
        assert decision_for("HIGH") == "Attend"
        assert decision_for("MEDIUM") == "Track*"
        assert decision_for("LOW") == "Track"
        assert decision_for("nonsense") == "Track"   # unknown degrades to Track


# ------------------------------------------------------------ exploit refinement

class TestApplyExploit:
    def test_no_exploit_changes_nothing(self):
        assert apply_exploit("HIGH", cve(), exploit_exists=False) == ("HIGH", None)

    @pytest.mark.parametrize("start,expected", [("MEDIUM", "HIGH"), ("HIGH", "CRITICAL")])
    def test_escalates_one_level(self, start, expected):
        new, note = apply_exploit(start, cve(), exploit_exists=True)
        assert new == expected
        assert rank(new) - rank(start) == 1
        assert "escalated" in note

    def test_critical_only_annotated(self):
        """Already at the top: record the evidence, do not (cannot) escalate."""
        new, note = apply_exploit("CRITICAL", cve(), exploit_exists=True)
        assert new == "CRITICAL"
        assert note and "escalated" not in note

    def test_low_is_not_escalated(self):
        """
        LOW is out of the actionable set; an exploit must not drag it in. The
        evidence is still recorded — annotating without escalating is the point.
        """
        new, _ = apply_exploit("LOW", cve(), exploit_exists=True)
        assert new == "LOW"


# ------------------------------------------------------------ context refinement

class TestApplyContext:
    def test_no_cluster_changes_nothing(self):
        assert apply_context("HIGH", cve(), None) == ("HIGH", None)
        assert apply_context("HIGH", cve(), context(available=False)) == ("HIGH", None)

    def test_not_deployed_deescalates_to_low(self):
        new, note = apply_context("CRITICAL", cve(epss=0.5), context(deployed=False))
        assert new == "LOW"
        assert "not deployed" in note

    @pytest.mark.parametrize("ctx_kwargs,reason", [
        ({"exposed": True}, "internet-facing"),
        ({"privileged": True}, "privileged"),
        ({"sa_privileged": True}, "privileged"),
    ])
    def test_escalates_exploitable_high(self, ctx_kwargs, reason):
        new, note = apply_context("HIGH", cve(epss=0.06), context(**ctx_kwargs))
        assert new == "CRITICAL"
        assert reason in note

    def test_escalation_needs_real_exploitability(self):
        """Exposure alone must not escalate — EPSS below 0.05 stays HIGH."""
        assert apply_context("HIGH", cve(epss=0.04), context(exposed=True)) == ("HIGH", None)

    def test_deescalates_borderline_internal_critical(self):
        new, note = apply_context("CRITICAL", cve(epss=0.15), context())
        assert new == "HIGH"
        assert "internal-only" in note

    def test_kev_critical_is_never_deescalated(self):
        """
        The noise-reduction rule must not be able to demote a known-exploited CVE;
        that would break the KEV-recall guarantee that the evaluation reports.
        """
        assert apply_context("CRITICAL", cve(epss=0.15, in_kev=True), context()) \
            == ("CRITICAL", None)

    def test_high_epss_critical_is_never_deescalated(self):
        assert apply_context("CRITICAL", cve(epss=0.5), context()) == ("CRITICAL", None)

    @pytest.mark.parametrize("priority", ["MEDIUM", "LOW"])
    def test_low_tiers_untouched_by_exposure(self, priority):
        """Context re-ranks the actionable set; it never invents new actionable work."""
        assert apply_context(priority, cve(epss=0.06), context(exposed=True)) \
            == (priority, None)


# ------------------------------------------------------------ runtime refinement

class TestApplyRuntime:
    def test_no_signal_changes_nothing(self):
        assert apply_runtime("HIGH", cve(), None) == ("HIGH", None)
        assert apply_runtime("HIGH", cve(), runtime(available=False)) == ("HIGH", None)
        assert apply_runtime("HIGH", cve(), runtime(count=0)) == ("HIGH", None)

    @pytest.mark.parametrize("falco_priority", ["Emergency", "Alert", "Critical", "Error"])
    def test_critical_tier_escalates_high(self, falco_priority):
        new, note = apply_runtime("HIGH", cve(), runtime(max_priority=falco_priority))
        assert new == "CRITICAL"
        assert "escalated HIGH->CRITICAL" in note

    @pytest.mark.parametrize("falco_priority", ["Warning", "Notice", "Informational", "Debug"])
    def test_lower_tier_annotates_only(self, falco_priority):
        """A shell in a container is worth recording, not worth escalating."""
        new, note = apply_runtime("HIGH", cve(), runtime(max_priority=falco_priority))
        assert new == "HIGH"
        assert note is not None

    def test_runtime_never_deescalates(self):
        """
        Runtime is one-directional by design: absence of alerts is not evidence of
        safety (Falco only sees what a rule matches), so it may never demote.
        """
        for priority in LADDER:
            new, _ = apply_runtime(priority, cve(), runtime(max_priority="Critical"))
            assert rank(new) >= rank(priority)

    @pytest.mark.parametrize("priority", ["MEDIUM", "LOW"])
    def test_low_tiers_not_escalated(self, priority):
        new, _ = apply_runtime(priority, cve(), runtime(max_priority="Critical"))
        assert new == priority


# ------------------------------------------- the regression that matters most

class TestEscalationCap:
    """
    Guards the 17->155 escalation-stacking bug: exploit + context + runtime all
    firing on one finding must not lift it more than one level in total.

    This is the reliability property the paper claims, so it is asserted directly
    rather than inferred from the aggregate counts.
    """

    def test_all_three_signals_move_at_most_one_level(self):
        finding = cve(epss=0.06, cvss=8.0, severity="HIGH")   # base -> HIGH
        base, _ = classify_priority(finding, in_kev=False)
        assert base == "HIGH"

        result = analyze(
            finding, in_kev=False,
            context=context(exposed=True, privileged=True),
            exploit_exists=True,
            runtime=runtime(max_priority="Critical"),
        )
        assert rank(result["priority"]) - rank(base) <= 1, (
            f"stacked {base} -> {result['priority']}: {result['notes']}")
        assert result["priority"] == "CRITICAL"
        assert result["decision"] == "Act"

    def test_exploit_plus_runtime_cannot_stack_two_levels(self):
        """
        Regression for a stacking path the per-refinement caps did NOT close:
        exploit lifts MEDIUM->HIGH, then runtime lifts HIGH->CRITICAL, moving a
        finding two levels above its base. Found by this suite on 2026-08-25.

        A MEDIUM base means EPSS 0.02 — five times below the Act threshold. No
        combination of corroborating context should make that Act.
        """
        finding = cve(epss=0.02, cvss=5.0, severity="MEDIUM")   # base -> MEDIUM
        assert classify_priority(finding, in_kev=False)[0] == "MEDIUM"
        result = analyze(
            finding, in_kev=False,
            exploit_exists=True,
            runtime=runtime(max_priority="Critical"),
        )
        assert result["priority"] == "HIGH", (
            f"MEDIUM base stacked to {result['priority']}: {result['notes']}")

    def test_every_base_tier_is_capped_at_plus_one(self):
        """
        The bound is a property of the tool, not of which signals happened to fire:
        assert it across every base tier with all three refinements firing at once.
        """
        bases = {
            "LOW":      cve(epss=0.001, cvss=2.0, severity="LOW"),
            "MEDIUM":   cve(epss=0.02, cvss=5.0, severity="MEDIUM"),
            "HIGH":     cve(epss=0.06, cvss=8.0, severity="HIGH"),
            "CRITICAL": cve(epss=0.5, cvss=9.0, severity="CRITICAL"),
        }
        for expected_base, finding in bases.items():
            base, _ = classify_priority(finding, in_kev=False)
            assert base == expected_base, f"fixture drift: {base} != {expected_base}"
            result = analyze(
                finding, in_kev=False,
                context=context(exposed=True, privileged=True),
                exploit_exists=True,
                runtime=runtime(max_priority="Critical"),
            )
            assert rank(result["priority"]) - rank(base) <= 1, (
                f"{base} stacked to {result['priority']}: {result['notes']}")

    def test_cap_does_not_restrict_deescalation(self):
        """
        The cap is one-directional. Noise reduction must still be free to drop a
        finding several levels — 'not deployed here' means exactly that.
        """
        result = analyze(
            cve(epss=0.5, cvss=9.8, severity="CRITICAL"), in_kev=False,
            context=context(deployed=False),
        )
        assert result["priority"] == "LOW"

    def test_analyze_is_idempotent_on_the_decision(self):
        """Re-running the same inputs must not compound the refinements."""
        finding = cve(epss=0.06, cvss=8.0, severity="HIGH")
        kwargs = dict(in_kev=False, context=context(exposed=True),
                      exploit_exists=True, runtime=runtime())
        first = analyze(finding, **kwargs)
        second = analyze(finding, **kwargs)
        assert first["priority"] == second["priority"]
        assert first["notes"] == second["notes"]

    def test_notes_record_every_signal_that_fired(self):
        """
        The rationale is the audit trail — a decision with no recorded reason is
        not defensible to an auditor, so absence of notes is a failure.
        """
        result = analyze(
            cve(epss=0.06, cvss=8.0, severity="HIGH"), in_kev=False,
            context=context(exposed=True), exploit_exists=True,
            runtime=runtime(max_priority="Critical"),
        )
        assert result["notes"], "refinements fired but recorded no rationale"


class TestAnalyzeEndToEnd:
    def test_clean_finding_stays_track(self):
        result = analyze(cve(epss=0.0001, cvss=2.0, severity="LOW"), in_kev=False)
        assert result["priority"] == "LOW"
        assert result["decision"] == "Track"
        assert result["notes"] == []

    def test_kev_finding_is_act_with_no_cluster(self):
        result = analyze(cve(epss=0.0, in_kev=True), in_kev=True)
        assert result["decision"] == "Act"

    def test_not_deployed_beats_everything_else(self):
        """An image that isn't running here is not this cluster's problem."""
        result = analyze(
            cve(epss=0.5, cvss=9.8, severity="CRITICAL"), in_kev=False,
            context=context(deployed=False), exploit_exists=True,
        )
        assert result["priority"] == "LOW"
