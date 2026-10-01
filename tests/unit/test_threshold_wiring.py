"""
Threshold overrides must actually reach the decision path.

The defect this guards against
------------------------------
`run.py thresholds` printed an ACTIVE column built from `Thresholds.from_env()` and
flagged any value that differed from the default. The pipeline, however, called
`ssvc.analyze` without passing thresholds at all, so it always used the module defaults.
Setting `K_CAVP_EPSS_ACT=0.05` therefore produced a report claiming the override was in
force while every decision in it used 0.10.

That is the worst shape a bug can take in an evaluation tool: it is invisible, it is
confidently mislabelled, and it would have silently invalidated issue #24's robustness
experiments on Dataset B -- which are run precisely by varying these values per run.

These tests assert the wiring end to end rather than the plumbing in isolation, because
the plumbing was never broken; the connection was.
"""

import pytest

from src.triage import engine
from src.triage.thresholds import DEFAULTS, Thresholds


def cve(cve_id="CVE-2024-0001", epss=0.06, cvss=8.0, severity="HIGH"):
    return {"cve_id": cve_id, "epss_score": epss, "cvss_score": cvss,
            "severity": severity, "affected_packages": ["openssl"]}


def priorities(findings):
    # The engine emits findings keyed on "cve", not "cve_id" -- the report schema, not
    # the dataset schema.
    return {f["cve"]: f["priority"] for f in findings}


class TestEnvironmentOverridesReachTheDecision:

    def test_default_epss_act_leaves_a_006_finding_below_act(self, monkeypatch):
        monkeypatch.delenv("K_CAVP_EPSS_ACT", raising=False)
        out = engine.analyze_cves([cve(epss=0.06)], set(), llm=None, verbose=False)
        assert priorities(out)["CVE-2024-0001"] == "HIGH"

    def test_lowering_epss_act_via_env_promotes_the_same_finding(self, monkeypatch):
        """The exact scenario the broken wiring reported as working."""
        monkeypatch.setenv("K_CAVP_EPSS_ACT", "0.05")
        out = engine.analyze_cves([cve(epss=0.06)], set(), llm=None, verbose=False)
        assert priorities(out)["CVE-2024-0001"] == "CRITICAL"

    def test_raising_epss_act_via_env_demotes_a_finding(self, monkeypatch):
        monkeypatch.setenv("K_CAVP_EPSS_ACT", "0.90")
        out = engine.analyze_cves([cve(epss=0.5)], set(), llm=None, verbose=False)
        assert priorities(out)["CVE-2024-0001"] != "CRITICAL"

    def test_an_explicit_thresholds_argument_wins_over_the_environment(self, monkeypatch):
        monkeypatch.setenv("K_CAVP_EPSS_ACT", "0.05")
        out = engine.analyze_cves([cve(epss=0.06)], set(), llm=None, verbose=False,
                                  thresholds=DEFAULTS)
        assert priorities(out)["CVE-2024-0001"] == "HIGH"

    def test_a_malformed_override_raises_rather_than_reverting(self, monkeypatch):
        """
        A sweep that quietly fell back to the default would label its results with a
        threshold it never applied -- the same class of error, one layer down.
        """
        monkeypatch.setenv("K_CAVP_EPSS_ACT", "not-a-number")
        with pytest.raises(ValueError):
            engine.analyze_cves([cve()], set(), llm=None, verbose=False)

    def test_the_bound_is_overridable_through_the_same_path(self, monkeypatch):
        """
        Experiment 6B varies exactly this value on Dataset B, so it has to travel the
        same route as the thresholds rather than being a separate mechanism.
        """
        monkeypatch.setenv("K_CAVP_MAX_ESCALATION_LEVELS", "0")
        out = engine.analyze_cves([cve(epss=0.02, severity="MEDIUM", cvss=5.0)], set(),
                                  llm=None, verbose=False)
        # With no upward refinement permitted the finding cannot leave its base tier.
        assert priorities(out)["CVE-2024-0001"] == "MEDIUM"


class TestThresholdsAreResolvedOncePerRun:

    def test_one_run_uses_a_single_threshold_set(self, monkeypatch):
        """
        Re-reading the environment per finding would let a value changed mid-run split
        one report across two threshold sets, which no caller could detect afterwards.
        """
        monkeypatch.setenv("K_CAVP_EPSS_ACT", "0.05")
        calls = []
        real = Thresholds.from_env

        def counting_from_env(*args, **kwargs):
            calls.append(1)
            return real(*args, **kwargs)

        monkeypatch.setattr(Thresholds, "from_env", counting_from_env)
        engine.analyze_cves([cve(f"CVE-2024-{i:04d}") for i in range(25)], set(),
                            llm=None, verbose=False)
        assert len(calls) == 1
