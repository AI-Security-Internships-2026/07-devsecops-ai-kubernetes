"""
Generated-policy safety.

Image names and CVE IDs come from scan data, which is attacker-influenced in a
supply-chain scenario, and they get interpolated into the YAML/Rego we emit. A
hostile value that escapes its string context could add or weaken policy rules,
so these tests are about injection, not formatting. This was flagged in review.
"""

import json

import pytest
import yaml

from src.enforce.gatekeeper import (
    _yaml_str,
    generate_policies,
    safe_cve_ids,
    sanitize_image,
)


class TestSanitizeImage:
    def test_keeps_a_legal_reference_intact(self):
        image = "ghcr.io/org/app:v1.2.3"
        assert sanitize_image(image) == image

    def test_keeps_a_digest_reference_intact(self):
        image = "registry.io/app@sha256:abc123"
        assert sanitize_image(image) == image

    @pytest.mark.parametrize("hostile", [
        'app:1.0"\nprivileged: true',      # break out of a quoted scalar
        "app:1.0 {malicious: yaml}",       # inject a flow mapping
        "app:1.0'; DROP TABLE",            # quote injection
        "app:1.0\n- extra: item",          # inject a list entry
        "app:1.0\r\nkey: value",           # CRLF injection
        "app:1.0\tkey",                    # tab
    ])
    def test_strips_everything_that_could_escape_a_string(self, hostile):
        out = sanitize_image(hostile)
        for ch in '"\'\n\r\t{}[]; ':
            assert ch not in out, f"{ch!r} survived sanitisation of {hostile!r}"

    def test_truncates_absurd_length(self):
        assert len(sanitize_image("a" * 5000)) == 255

    @pytest.mark.parametrize("value", ["", None])
    def test_empty_input_is_safe(self, value):
        assert sanitize_image(value) == ""


class TestSafeCveIds:
    def test_keeps_well_formed_ids_and_uppercases(self):
        assert safe_cve_ids([{"cve": "CVE-2021-41773"},
                             {"cve": "cve-2023-50387"}]) == \
            ["CVE-2021-41773", "CVE-2023-50387"]

    @pytest.mark.parametrize("bad", [
        "CVE-2021-41773; rm -rf /",
        'CVE-2021-41773"\ninjected: true',
        "NOT-A-CVE",
        "CVE-21-1",              # malformed year / sequence
        "",
        "CVE-2021-41773 extra",
    ])
    def test_rejects_anything_not_a_bare_cve_id(self, bad):
        assert safe_cve_ids([{"cve": bad}]) == []

    def test_missing_key_is_dropped(self):
        assert safe_cve_ids([{}, {"cve": None}]) == []


class TestYamlStr:
    @pytest.mark.parametrize("raw", [
        'has "quotes"',
        "has\nnewline",
        "has\\backslash",
        "has\ttab",
        "plain",
    ])
    def test_round_trips_through_a_yaml_parser(self, raw):
        """
        The escaping only counts if a real YAML parser reads back exactly what we
        put in — asserting on the rendered text would just re-state the encoder.
        """
        assert yaml.safe_load(f"value: {_yaml_str(raw)}") == {"value": raw}

    def test_output_is_a_quoted_scalar(self):
        assert _yaml_str("x").startswith('"')


class TestGeneratePolicies:
    def test_output_is_parseable_yaml(self):
        text = generate_policies("nginx:1.21", [{"cve": "CVE-2021-41773"}])
        docs = [d for d in yaml.safe_load_all(text) if d]
        assert docs, "generated no YAML documents"
        for doc in docs:
            assert "kind" in doc

    def test_hostile_image_cannot_inject_policy(self):
        """
        The end-to-end property: a malicious image name must not be able to add a
        document, a key, or a rule to the generated policy set.
        """
        clean = [d for d in yaml.safe_load_all(
            generate_policies("app:1.0", [{"cve": "CVE-2021-41773"}])) if d]
        hostile = [d for d in yaml.safe_load_all(
            generate_policies('app:1.0"\n---\nkind: Injected\n',
                              [{"cve": "CVE-2021-41773"}])) if d]
        assert len(hostile) == len(clean)
        assert not any(d.get("kind") == "Injected" for d in hostile)

    def test_hostile_cve_id_is_dropped_not_rendered(self):
        text = generate_policies("app:1.0", [{"cve": 'CVE-1\n---\nkind: Injected'}])
        assert "Injected" not in text
        for doc in [d for d in yaml.safe_load_all(text) if d]:
            assert doc.get("kind") != "Injected"

    def test_empty_act_list_still_produces_valid_policy(self):
        docs = [d for d in yaml.safe_load_all(generate_policies("app:1.0", [])) if d]
        assert docs
