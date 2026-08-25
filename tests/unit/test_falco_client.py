"""
Falco alert parsing, image matching, and the guards around a hostile/empty stream.

The parser sits between untrusted input (a kernel-level alert stream) and the
scoring engine, so the tests here are mostly about surviving bad input without
either crashing or silently inventing alerts.
"""

import pytest

from src.runtime.falco_client import (
    _image_from_fields,
    _is_existing_file,
    alerts_for_image,
    parse_falco_stream,
    summarize,
)


class TestIsExistingFile:
    """
    Regression guards. `parse_falco_stream` takes "a path OR raw text", so this
    predicate decides which — and both of these inputs used to reach the wrong
    branch and raise.
    """

    @pytest.mark.parametrize("value", ["", "   ", "\n"])
    def test_blank_is_not_a_file(self, value):
        """
        Path("") normalises to Path("."), whose exists() is True — so an empty
        stream used to be treated as a path and read the current DIRECTORY
        (IsADirectoryError). This is the `[Errno 21] Is a directory: '.'` bug.
        """
        assert _is_existing_file(value) is False

    def test_alert_text_is_not_a_file(self):
        """Raw JSON is text, not a path, and must not be probed as one."""
        assert _is_existing_file('{"rule":"x","priority":"Critical"}') is False

    def test_absurdly_long_value_is_not_a_file(self):
        """
        An over-long path makes Path() raise OSError on Windows rather than
        returning False, so the predicate has to catch it.
        """
        assert _is_existing_file("A" * 5000) is False

    def test_embedded_nul_is_not_a_file(self):
        assert _is_existing_file("alert\x00text") is False

    def test_real_file_is_detected(self, tmp_path):
        f = tmp_path / "alerts.json"
        f.write_text("{}", encoding="utf-8")
        assert _is_existing_file(str(f)) is True

    def test_directory_is_not_a_file(self, tmp_path):
        assert _is_existing_file(str(tmp_path)) is False


class TestParseFalcoStream:
    def test_parses_valid_alerts_and_skips_junk(self, falco_stream_text):
        """Blank lines, the startup banner and malformed JSON must not break parsing."""
        alerts = parse_falco_stream(falco_stream_text)
        assert len(alerts) == 2
        assert [a["priority"] for a in alerts] == ["Critical", "Notice"]

    def test_extracts_the_fields_scoring_depends_on(self, falco_stream_text):
        first = parse_falco_stream(falco_stream_text)[0]
        assert first["rule"] == "Read sensitive file untrusted"
        assert first["image"] == "vuln-demo:1.0"
        assert first["namespace"] == "default"
        assert first["pod"] == "vuln-demo-abc"
        assert first["process"] == "cat"

    def test_empty_stream_yields_no_alerts(self):
        assert parse_falco_stream("") == []
        assert parse_falco_stream("\n\n  \n") == []

    def test_reads_from_a_file(self, tmp_path, falco_stream_text):
        f = tmp_path / "falco.jsonl"
        f.write_text(falco_stream_text, encoding="utf-8")
        assert len(parse_falco_stream(str(f))) == 2

    def test_missing_output_fields_does_not_crash(self):
        """
        A rule can fire with no container context at all (host-level alerts do).
        Those must parse to an alert with no image, not raise.
        """
        alerts = parse_falco_stream('{"rule":"r","priority":"Warning"}')
        assert len(alerts) == 1
        assert alerts[0]["image"] == ""


class TestImageFromFields:
    def test_repo_and_tag(self):
        assert _image_from_fields({
            "container.image.repository": "nginx",
            "container.image.tag": "1.21",
        }) == "nginx:1.21"

    def test_repo_without_tag(self):
        assert _image_from_fields({"container.image.repository": "nginx"}) == "nginx"

    def test_no_image_fields(self):
        assert _image_from_fields({}) == ""


class TestAlertsForImage:
    def test_matches_the_right_image_only(self, falco_stream_text):
        alerts = parse_falco_stream(falco_stream_text)
        assert len(alerts_for_image(alerts, "vuln-demo:1.0")) == 1
        assert len(alerts_for_image(alerts, "nginx:1.21")) == 1
        assert alerts_for_image(alerts, "redis:6.2") == []

    def test_matches_across_registry_prefixes(self, falco_stream_text):
        """
        Falco reports the image as the runtime sees it; Trivy scans the ref the
        user typed. Those differ by registry host, so matching must be
        registry-agnostic or the runtime signal silently never lands.
        """
        alerts = parse_falco_stream(falco_stream_text)
        assert len(alerts_for_image(alerts, "docker.io/library/nginx:1.21")) == 1

    def test_alerts_without_an_image_never_match(self):
        alerts = parse_falco_stream('{"rule":"r","priority":"Critical"}')
        assert alerts_for_image(alerts, "nginx:1.21") == []


class TestSummarize:
    def test_counts_by_priority_and_image(self, falco_stream_text):
        s = summarize(parse_falco_stream(falco_stream_text))
        assert s["total"] == 2
        assert s["by_priority"] == {"Critical": 1, "Notice": 1}
        assert s["by_image"] == {"vuln-demo:1.0": 1, "nginx:1.21": 1}

    def test_empty(self):
        assert summarize([]) == {"total": 0, "by_priority": {}, "by_image": {}}
