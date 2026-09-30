"""
Pre-deployment vs cluster mode separation (issue #19, item 6).

Why this exists
---------------
The deployment-context rule "image is not running here, so de-escalate" is correct
against a live cluster and actively dangerous in a CI gate, where the image is not
running *by definition*. Applying it pre-deployment files every finding as Track at
exactly the point the pipeline is meant to block a bad image.

That defect shipped once. It was partially patched by exempting CISA KEV findings, which
rescued the known-exploited subset and left everything else still wrongly deferred --
the half-fix is precisely why the mode has to be explicit rather than inferred from
whichever signals a caller happened to supply.

These tests pin both rule sets and, importantly, pin the *difference* between them.
"""

import pytest

from src.triage.ssvc import (MODE_CLUSTER, MODE_PRE_DEPLOYMENT, MODES, analyze,
                             apply_context, apply_runtime, classify_priority,
                             resolve_mode)


def cve(cve_id="CVE-2024-0001", epss=0.02, cvss=8.0, severity="HIGH", in_kev=False,
        packages=None):
    return {"cve_id": cve_id, "epss_score": epss, "cvss_score": cvss,
            "severity": severity, "in_kev": in_kev,
            "affected_packages": packages or ["coreutils"]}


def ctx(available=True, deployed=True, exposed=False, privileged=False):
    return {"available": available, "deployed": deployed, "exposed": exposed,
            "privileged": privileged}


def runtime(available=True, count=1, max_priority="Critical", alerts=None):
    return {"available": available, "count": count, "max_priority": max_priority,
            "rules": ["Read sensitive file"],
            "alerts": alerts if alerts is not None else [
                {"priority": "Critical", "rule": "Read sensitive file",
                 "packages": ["coreutils"], "process": "cat",
                 "exepath": "/usr/bin/cat"}]}


class TestResolveMode:

    def test_explicit_mode_wins_over_inference(self):
        assert resolve_mode(ctx(), None, MODE_PRE_DEPLOYMENT) == MODE_PRE_DEPLOYMENT
        assert resolve_mode(None, None, MODE_CLUSTER) == MODE_CLUSTER

    def test_unknown_mode_raises_rather_than_defaulting(self):
        """
        A typo must not silently select the permissive rule set. Falling back would
        produce results labelled with a mode that never ran.
        """
        with pytest.raises(ValueError, match="unknown mode"):
            resolve_mode(None, None, "clusterr")

    def test_no_signals_infers_pre_deployment(self):
        assert resolve_mode(None, None) == MODE_PRE_DEPLOYMENT
        assert resolve_mode(ctx(available=False), None) == MODE_PRE_DEPLOYMENT

    def test_available_cluster_context_infers_cluster(self):
        assert resolve_mode(ctx(), None) == MODE_CLUSTER

    def test_runtime_evidence_alone_infers_cluster(self):
        """
        Falco alerts can only come from a running container, so they prove the workload
        is live even when the Kubernetes API was unreachable. Inferring pre-deployment
        from the missing API alone would silence genuine runtime escalations on every
        context-lookup failure.
        """
        assert resolve_mode(None, runtime()) == MODE_CLUSTER
        assert resolve_mode(ctx(available=False), runtime()) == MODE_CLUSTER

    def test_unavailable_runtime_does_not_imply_cluster(self):
        assert resolve_mode(None, runtime(available=False)) == MODE_PRE_DEPLOYMENT

    def test_every_mode_is_accepted(self):
        for mode in MODES:
            assert resolve_mode(None, None, mode) == mode


class TestNotDeployedIsNotEvidencePreDeployment:
    """The defect this mode split exists to fix."""

    NOT_DEPLOYED = ctx(deployed=False)

    def test_cluster_mode_de_escalates_a_non_kev_finding(self):
        priority, note = apply_context("HIGH", cve(), self.NOT_DEPLOYED,
                                       mode=MODE_CLUSTER)
        assert priority == "LOW"
        assert "not deployed" in note

    def test_pre_deployment_mode_does_not_de_escalate(self):
        priority, note = apply_context("HIGH", cve(), self.NOT_DEPLOYED,
                                       mode=MODE_PRE_DEPLOYMENT)
        assert priority == "HIGH"
        assert "pre-deployment" in note
        assert "not de-escalated" in note

    @pytest.mark.parametrize("priority", ["CRITICAL", "HIGH", "MEDIUM"])
    def test_no_tier_is_de_escalated_pre_deployment(self, priority):
        """
        The KEV exemption rescued only the KEV subset. The mode must rescue every tier,
        which is the whole difference between the half-fix and the fix.
        """
        result, _ = apply_context(priority, cve(in_kev=False), self.NOT_DEPLOYED,
                                  mode=MODE_PRE_DEPLOYMENT)
        assert result == priority

    def test_kev_exemption_still_applies_in_cluster_mode(self):
        """The exemption is still needed where the rule still fires."""
        priority, note = apply_context("CRITICAL", cve(in_kev=True), self.NOT_DEPLOYED,
                                       mode=MODE_CLUSTER)
        assert priority == "CRITICAL"
        assert "KEV" in note

    def test_a_ci_gate_keeps_its_actionable_queue(self):
        """
        End to end: a High finding on an image that is not running must stay actionable
        when the scan is a pre-deployment gate.
        """
        finding = cve(epss=0.05, cvss=8.8, severity="HIGH")
        gate = analyze(finding, in_kev=False, context=self.NOT_DEPLOYED,
                       mode=MODE_PRE_DEPLOYMENT)
        live = analyze(finding, in_kev=False, context=self.NOT_DEPLOYED,
                       mode=MODE_CLUSTER)
        assert gate["priority"] == "HIGH"
        assert gate["decision"] == "Attend"
        assert live["priority"] == "LOW"
        assert live["decision"] == "Track"


class TestRuntimeIsUnavailablePreDeployment:

    def test_attributed_alert_escalates_in_cluster_mode(self):
        priority, note = apply_runtime("HIGH", cve(), runtime(), mode=MODE_CLUSTER)
        assert priority == "CRITICAL"
        assert "escalated" in note

    def test_the_same_alert_never_escalates_pre_deployment(self):
        priority, note = apply_runtime("HIGH", cve(), runtime(),
                                       mode=MODE_PRE_DEPLOYMENT)
        assert priority == "HIGH"
        assert "pre-deployment" in note

    def test_supplied_alerts_are_recorded_not_discarded(self):
        """Silently dropping the evidence would leave no trace of a caller error."""
        _, note = apply_runtime("HIGH", cve(), runtime(count=3),
                                mode=MODE_PRE_DEPLOYMENT)
        assert "3 runtime alert(s)" in note


class TestModeIsRecorded:
    """A stored decision must say which rule set produced it."""

    def test_analyze_returns_the_resolved_mode(self):
        assert analyze(cve(), False)["mode"] == MODE_PRE_DEPLOYMENT
        assert analyze(cve(), False, context=ctx())["mode"] == MODE_CLUSTER

    def test_explicit_mode_is_reported_back(self):
        result = analyze(cve(), False, context=ctx(), mode=MODE_PRE_DEPLOYMENT)
        assert result["mode"] == MODE_PRE_DEPLOYMENT

    def test_bad_mode_raises_from_analyze(self):
        with pytest.raises(ValueError):
            analyze(cve(), False, mode="nonsense")


class TestModeDoesNotDisturbTheBase:
    """
    Mode may only affect the context and runtime refinements. If it moved the base
    classification, two modes would disagree about evidence neither of them observed.
    """

    @pytest.mark.parametrize("mode", MODES)
    @pytest.mark.parametrize("epss,expected", [(0.5, "CRITICAL"), (0.05, "HIGH"),
                                               (0.02, "HIGH"), (0.0, "LOW")])
    def test_base_classification_is_mode_independent(self, mode, epss, expected):
        finding = cve(epss=epss, cvss=8.0, severity="HIGH")
        assert classify_priority(finding, in_kev=False)[0] == expected
        assert analyze(finding, in_kev=False, mode=mode)["priority"] == expected

    @pytest.mark.parametrize("mode", MODES)
    def test_exploit_refinement_is_mode_independent(self, mode):
        finding = cve(epss=0.02, cvss=5.0, severity="MEDIUM")
        assert analyze(finding, in_kev=False, exploit_exists=True,
                       mode=mode)["priority"] == "HIGH"

    @pytest.mark.parametrize("mode", MODES)
    def test_deployed_and_exposed_escalation_works_in_both_modes(self, mode):
        """
        Escalation from positive observations is sound in either mode: if we can see the
        pod is internet-facing, that is evidence regardless of why we are scanning.
        """
        finding = cve(epss=0.06, cvss=8.0, severity="HIGH")
        result = analyze(finding, in_kev=False,
                         context=ctx(deployed=True, exposed=True), mode=mode)
        assert result["priority"] == "CRITICAL"
