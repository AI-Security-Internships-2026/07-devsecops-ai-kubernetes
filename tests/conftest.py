"""
Shared fixtures for the unit suite.

Everything here is a plain dict or a temp file: no network, no cluster, no Trivy,
no LLM. The scoring core is pure, so it is tested as pure — which is also what
makes the paper's numbers reproducible from committed inputs.
"""

import json
import sys
from pathlib import Path

import pytest

# Import the package from the repo root regardless of where pytest is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def cve(cve_id="CVE-2024-0001", epss=0.0, cvss=0.0, severity="MEDIUM", in_kev=False,
        packages=None):
    """
    Build one finding in the shape the scoring functions expect.

    Keyword-only in spirit: every threshold in the SSVC ladder keys off epss,
    cvss, severity or KEV membership, so tests set exactly the field under test
    and leave the rest at values that cannot accidentally trip another rule.
    """
    return {
        "cve_id": cve_id,
        "epss_score": epss,
        "cvss_score": cvss,
        "severity": severity,
        "in_kev": in_kev,
        "affected_packages": packages or [],
    }


def context(available=True, deployed=True, exposed=False, privileged=False,
            sa_privileged=False, exposure_type="", namespace="default"):
    """Kubernetes deployment context, as `derive_context` returns it."""
    return {
        "available": available,
        "deployed": deployed,
        "exposed": exposed,
        "privileged": privileged,
        "sa_privileged": sa_privileged,
        "exposure_type": exposure_type,
        "namespace": namespace,
    }


def runtime(available=True, count=1, max_priority="Critical", rules=None,
            alerts=None):
    """
    Falco runtime signal, as `_build_runtime_provider` returns it.

    `alerts` carries the attributed evidence. Escalation requires it: an alert with
    no `packages` entry matching the finding cannot raise the decision (issue #17).
    """
    sig = {
        "available": available,
        "count": count,
        "max_priority": max_priority,
        "rules": rules or ["Terminal shell in container"],
    }
    if alerts is not None:
        sig["alerts"] = alerts
    return sig


def alert(priority="Critical", rule="Read sensitive file untrusted", packages=(),
          process="cat", exepath="/usr/bin/cat", file="/etc/shadow", tags=()):
    """One attributed Falco alert, in the shape apply_runtime consumes."""
    return {
        "priority": priority, "rule": rule, "packages": list(packages),
        "process": process, "exepath": exepath, "file": file, "tags": list(tags),
    }


@pytest.fixture
def make_cve():
    return cve


@pytest.fixture
def make_context():
    return context


@pytest.fixture
def make_runtime():
    return runtime


# A real Falco alert line, kept in the shape Falco 0.44 actually emits (verified
# against a live capture on 2026-08-25) so the parser is tested against the real
# contract rather than an idealised one.
FALCO_LINE_CRITICAL = json.dumps({
    "time": "2026-08-25T10:12:05.777Z",
    "rule": "Read sensitive file untrusted",
    "priority": "Critical",
    "output": "Sensitive file opened for reading by non-trusted program",
    "output_fields": {
        "k8s.ns.name": "default",
        "k8s.pod.name": "vuln-demo-abc",
        "container.name": "vuln-demo",
        "container.image.repository": "vuln-demo",
        "container.image.tag": "1.0",
        "proc.name": "cat",
    },
})

FALCO_LINE_NOTICE = json.dumps({
    "time": "2026-08-25T10:12:09.114Z",
    "rule": "Terminal shell in container",
    "priority": "Notice",
    "output": "A shell was spawned in a container",
    "output_fields": {
        "k8s.ns.name": "default",
        "k8s.pod.name": "web-xyz",
        "container.name": "nginx",
        "container.image.repository": "nginx",
        "container.image.tag": "1.21",
        "proc.name": "sh",
    },
})


@pytest.fixture
def falco_stream_text():
    """Two alerts on two different images, plus noise the parser must survive."""
    return "\n".join([
        FALCO_LINE_CRITICAL,
        "",                                   # blank line
        "Falco initialized with configuration",   # non-JSON banner line
        "{not valid json",                    # malformed
        FALCO_LINE_NOTICE,
    ])


@pytest.fixture
def triage_run_file(tmp_path):
    """
    A minimal triage_run.json in the committed schema, for the evaluator tests.

    Two findings: one KEV-and-actionable, one low-severity noise. Small enough
    that every number the evaluator prints can be checked by hand.
    """
    data = {
        "container_image": "test-image:1.0",
        "summary": {
            "critical_act": 1, "high_attend": 0,
            "medium_track_star": 0, "low_track": 1,
            "alert_reduction_pct": 50.0,
        },
        "findings": [
            {
                "cve_id": "CVE-2021-41773",
                "cvss_score": 7.5, "cvss_severity": "HIGH",
                "epss_score": 0.94, "kev_status": True,
                "priority": "CRITICAL", "ssvc_decision": "Act",
                "decision_rationale": "in CISA KEV",
                "affected_packages": ["httpd"],
            },
            {
                "cve_id": "CVE-2024-9999",
                "cvss_score": 3.1, "cvss_severity": "LOW",
                "epss_score": 0.0004, "kev_status": False,
                "priority": "LOW", "ssvc_decision": "Track",
                "decision_rationale": "low EPSS",
                "affected_packages": ["libfoo"],
            },
        ],
    }
    path = tmp_path / "triage_run_test-image.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
