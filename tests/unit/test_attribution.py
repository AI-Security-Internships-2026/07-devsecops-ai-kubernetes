"""
Alert -> package attribution (issue #17).

The false-positive direction matters more than the false-negative one here: a wrong
attribution invents a causal link and escalates a finding on evidence that has nothing
to do with it, while a missed attribution only leaves the finding where the scores put
it. So most of these tests assert that something does NOT match.
"""

import pytest

from src.runtime.attribution import (
    attribute_alerts,
    attribution_rate,
    candidate_packages,
    implicated_packages,
    match_packages,
)
from src.runtime.falco_client import parse_falco_stream

# The exact alert a live Falco 0.44.1 capture produced on the DGX (2026-08-24),
# trimmed to the fields attribution reads. Using the real shape keeps these tests
# honest about the contract rather than an idealised version of it.
REAL_ALERT = {
    "rule": "Read sensitive file untrusted",
    "priority": "Warning",
    "image": "redis:6.2",
    "process": "cat",
    "exepath": "/usr/bin/cat",
    "cmdline": "cat /etc/shadow",
    "parent": "sh",
    "file": "/etc/shadow",
    "evt_type": "openat",
    "tags": ["T1555"],
}


class TestCandidatePackages:
    def test_resolves_a_coreutils_binary(self):
        cands = candidate_packages(REAL_ALERT)
        assert "coreutils" in cands
        assert "cat" in cands

    def test_resolves_a_shared_library_path(self):
        """libssl.so.3 must reach the name Trivy actually reports (libssl3)."""
        cands = candidate_packages(
            {"file": "/usr/lib/aarch64-linux-gnu/libssl.so.3", "process": "nginx"})
        assert {"libssl", "libssl3", "ssl"} <= cands

    @pytest.mark.parametrize("path,expected", [
        ("/usr/lib/python3/dist-packages/requests/api.py", "requests"),
        ("/usr/local/lib/python3.9/site-packages/urllib3/util.py", "urllib3"),
        ("/app/node_modules/lodash/index.js", "lodash"),
    ])
    def test_resolves_language_package_layouts(self, path, expected):
        """
        Language-level packages are where much of the CVE volume lives, and their
        on-disk layout names the package directly.
        """
        assert expected in candidate_packages({"file": path})

    def test_versioned_interpreter_also_offers_the_stem(self):
        cands = candidate_packages({"process": "python3.9", "exepath": "/usr/bin/python3.9"})
        assert "python3" in cands or "python" in cands

    def test_empty_alert_yields_nothing(self):
        assert candidate_packages({}) == set()

    def test_single_character_names_are_dropped(self):
        """Too short to be a meaningful package name; matching them invites noise."""
        assert candidate_packages({"process": "x"}) == set()


class TestMatching:
    @pytest.mark.parametrize("candidate,package", [
        ("coreutils", "coreutils"),
        ("CoreUtils", "coreutils"),          # case-insensitive
        ("libnghttp2", "libnghttp2-14"),     # Debian ABI suffix
        ("libssl3", "libssl3"),
        ("python3", "python3.11"),
    ])
    def test_matches(self, candidate, package):
        assert match_packages({candidate}, [package]) == {package}

    @pytest.mark.parametrize("candidate,package", [
        ("sh", "shadow"),          # the prefix trap this guard exists for
        ("cat", "catatonit"),
        ("ssl", "openssl"),        # substring, not prefix - must not match
        ("git", "github"),
        ("node", "nodejs-doc"),    # remainder starts with a letter
    ])
    def test_does_not_match_lookalikes(self, candidate, package):
        assert match_packages({candidate}, [package]) == set()

    def test_no_candidates_matches_nothing(self):
        assert match_packages(set(), ["coreutils"]) == set()


class TestImplicatedPackages:
    def test_links_the_real_alert_to_coreutils(self):
        assert implicated_packages(REAL_ALERT, ["coreutils", "libssl3"]) == {"coreutils"}

    def test_does_not_link_an_unrelated_package(self):
        """
        This is the whole point of #17: an alert about `cat` says nothing about a TLS
        library, so it must not be evidence about a TLS-library CVE.
        """
        assert implicated_packages(REAL_ALERT, ["libssl3", "libnghttp2-14"]) == set()

    def test_no_packages_in_scope(self):
        assert implicated_packages(REAL_ALERT, []) == set()


class TestAttributeAlerts:
    def test_annotates_each_alert_with_its_packages(self):
        out = attribute_alerts([REAL_ALERT], ["coreutils", "libssl3"])
        assert out[0]["packages"] == ["coreutils"]
        assert out[0]["rule"] == REAL_ALERT["rule"]      # original fields preserved

    def test_unattributable_alert_gets_an_empty_list(self):
        out = attribute_alerts([{"rule": "r", "priority": "Critical"}], ["coreutils"])
        assert out[0]["packages"] == []

    def test_rate_reports_how_often_the_link_was_made(self):
        """
        Reported in the evaluation so the paper can state the attribution rate rather
        than implying the link always exists.
        """
        out = attribute_alerts(
            [REAL_ALERT, {"rule": "r", "priority": "Critical"}], ["coreutils"])
        assert attribution_rate(out) == 0.5
        assert attribution_rate([]) == 0.0


class TestEndToEndFromRawFalcoJson:
    def test_parses_and_attributes_a_real_falco_line(self):
        """
        The full path: the raw JSON line Falco emits -> parsed record -> attribution.
        Guards the field names, which are the contract between Falco and this module.
        """
        raw = (
            '{"rule":"Read sensitive file untrusted","priority":"Warning",'
            '"time":"2026-08-24T20:49:35.516969748Z","tags":["T1555","container"],'
            '"output_fields":{"container.image.repository":"redis",'
            '"container.image.tag":"6.2","fd.name":"/etc/shadow","proc.name":"cat",'
            '"proc.exepath":"/usr/bin/cat","proc.cmdline":"cat /etc/shadow",'
            '"proc.pname":"sh","evt.type":"openat","k8s.pod.name":"internal-pod",'
            '"k8s.ns.name":"default"}}'
        )
        alerts = parse_falco_stream(raw)
        assert len(alerts) == 1
        a = alerts[0]
        assert a["exepath"] == "/usr/bin/cat"
        assert a["file"] == "/etc/shadow"
        assert a["cmdline"] == "cat /etc/shadow"
        assert a["image"] == "redis:6.2"
        assert a["tags"] == ["T1555"]      # non-technique tags filtered out

        assert implicated_packages(a, ["coreutils", "redis"]) == {"coreutils"}
        assert implicated_packages(a, ["redis"]) == set()
