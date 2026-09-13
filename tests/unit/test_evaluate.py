"""
The evaluation harness (`scripts/evaluate_triage.py`).

These numbers go straight into the paper, so the arithmetic is tested on fixtures
small enough to verify by hand. The subtle case is a finding that was escalated and
then clamped by the total-escalation cap: its rationale carries both notes, and
counting the escalation alone overstates the movement — enough to drive `Act before`
negative, which is how the miscount would surface.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "evaluate_triage",
    Path(__file__).resolve().parents[2] / "scripts" / "evaluate_triage.py")
ev = importlib.util.module_from_spec(_SPEC)
sys.modules["evaluate_triage"] = ev
_SPEC.loader.exec_module(ev)


def write_run(tmp_path, findings, image="demo:1.0", summary=None, name="triage_run_demo.json"):
    data = {
        "container_image": image,
        "summary": summary or {},
        "findings": findings,
    }
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def finding(cve_id="CVE-1", severity="HIGH", cvss=7.5, epss=0.06, kev=False,
            priority="HIGH", rationale=""):
    return {
        "cve_id": cve_id, "cvss_severity": severity, "cvss_score": cvss,
        "epss_score": epss, "kev_status": kev, "priority": priority,
        "decision_rationale": rationale,
    }


class TestLoadReports:
    def test_excludes_the_bare_latest_copy(self, tmp_path):
        """
        `triage_run.json` is a convenience copy of the most recent per-image file, so
        including it would double-count one image.
        """
        write_run(tmp_path, [finding()], name="triage_run_demo.json")
        write_run(tmp_path, [finding()], name="triage_run.json")
        assert len(ev.load_reports([str(tmp_path)])) == 1

    def test_missing_dir_yields_nothing(self, tmp_path):
        assert ev.load_reports([str(tmp_path / "nope")]) == []


class TestBaselines:
    def test_actionable_sets_and_reduction(self, tmp_path):
        findings = [
            finding("CVE-1", severity="HIGH",   epss=0.50, priority="CRITICAL"),
            finding("CVE-2", severity="HIGH",   epss=0.02, priority="HIGH"),
            finding("CVE-3", severity="LOW",    epss=0.001, priority="LOW"),
            finding("CVE-4", severity="MEDIUM", epss=0.001, priority="LOW"),
        ]
        r = ev.evaluate_one(str(write_run(tmp_path, findings)))
        assert r["total_cves"] == 4
        # CVSS-only keeps severity >= HIGH -> CVE-1, CVE-2
        assert r["methods"]["CVSS-only (sev>=HIGH)"]["actionable"] == 2
        # EPSS-only keeps >= 0.1 -> CVE-1
        assert r["methods"]["EPSS-only (>=0.1)"]["actionable"] == 1
        # Ours keeps CRITICAL + HIGH -> CVE-1, CVE-2
        assert r["methods"]["Ours (Act+Attend)"]["actionable"] == 2
        assert r["methods"]["Ours (Act+Attend)"]["reduction_pct"] == 50.0


class TestKevRecall:
    def test_recall_is_none_without_kev_findings(self, tmp_path):
        r = ev.evaluate_one(str(write_run(tmp_path, [finding()])))
        assert r["kev_total"] == 0
        for m in r["methods"].values():
            assert m["kev_recall"] is None

    def test_ours_keeps_every_kev_finding(self, tmp_path):
        """
        The 100% KEV-recall claim: a KEV CVE with negligible EPSS and LOW severity is
        dropped by both baselines but kept by ours.
        """
        findings = [finding("CVE-K", severity="LOW", cvss=2.0, epss=0.0001,
                            kev=True, priority="CRITICAL")]
        r = ev.evaluate_one(str(write_run(tmp_path, findings)))
        assert r["kev_total"] == 1
        assert r["methods"]["Ours (Act+Attend)"]["kev_recall"] == 1.0
        assert r["methods"]["CVSS-only (sev>=HIGH)"]["kev_recall"] == 0.0
        assert r["methods"]["EPSS-only (>=0.1)"]["kev_recall"] == 0.0


class TestContextRuntimeCounting:
    def test_capped_escalation_is_not_counted_as_reaching_act(self, tmp_path):
        """
        A finding escalated then clamped back never reached Act. Counting its
        escalation note would make Act-before negative, which is the tell.
        """
        findings = [
            finding("CVE-1", priority="CRITICAL",
                    rationale="escalated HIGH->CRITICAL: Falco Critical alert on "
                              "process cat -> package coreutils, which this CVE affects"),
            finding("CVE-2", priority="HIGH",
                    rationale="escalated MEDIUM->HIGH: public exploit code exists; "
                              "escalated HIGH->CRITICAL: Falco Critical alert; "
                              "capped CRITICAL->HIGH: refinements may raise a finding "
                              "at most one level above its MEDIUM base classification"),
        ]
        c = ev.evaluate_one(str(write_run(tmp_path, findings)))["context_runtime"]
        assert c["act_after"] == 1
        assert c["escalated_to_critical"] == 1
        assert c["capped"] == 1
        assert c["act_before"] == 0
        assert c["act_before"] >= 0, "capped escalations were double-counted"

    def test_deescalation_is_counted(self, tmp_path):
        findings = [finding("CVE-1", priority="HIGH",
                            rationale="de-escalated CRITICAL->HIGH: internal-only, "
                                      "not in CISA KEV (EPSS 0.150)")]
        c = ev.evaluate_one(str(write_run(tmp_path, findings)))["context_runtime"]
        assert c["deescalated_from_critical"] == 1
        assert c["act_before"] == 1     # it was Act before context demoted it

    def test_attribution_rate(self, tmp_path):
        findings = [
            finding("CVE-1", rationale="Falco Critical alert on process cat -> package "
                                       "coreutils, which this CVE affects"),
            finding("CVE-2", rationale="runtime activity on this image not attributable "
                                       "to this finding's package(s)"),
        ]
        c = ev.evaluate_one(str(write_run(tmp_path, findings)))["context_runtime"]
        assert c["runtime_attributed"] == 1
        assert c["runtime_unattributed"] == 1
        assert c["runtime_attribution_rate"] == 0.5

    def test_attribution_rate_is_none_without_runtime_signal(self, tmp_path):
        c = ev.evaluate_one(str(write_run(tmp_path, [finding()])))["context_runtime"]
        assert c["runtime_attribution_rate"] is None


class TestRenderMarkdown:
    def test_renders_all_five_sections(self, tmp_path):
        r = ev.evaluate_one(str(write_run(tmp_path, [finding()])))
        md = ev.render_markdown([r])
        for heading in ("## 1.", "## 2.", "## 3.", "## 4.", "## 5."):
            assert heading in md

    def test_handles_an_empty_findings_list(self, tmp_path):
        """An image with no CVEs must not divide by zero."""
        r = ev.evaluate_one(str(write_run(tmp_path, [])))
        assert r["total_cves"] == 0
        assert ev.render_markdown([r])
