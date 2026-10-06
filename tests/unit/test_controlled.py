"""
Dataset B -- controlled Kubernetes scenarios (issues #21, #24, #25).

Dataset B is expensive to collect: it needs a cluster, image pulls and a Falco install,
and it is gathered in one sitting. A flaw in the scenario definitions is therefore not a
test failure, it is a wasted session. These tests exist to catch that class of flaw
before anyone touches the VM.

Two of them encode mistakes already made and caught during design:

* comparing a scenario against a reference running a *different image*, which would score
  a handful of coincidentally-shared CVEs as a context effect;
* modelling the KEV exemption as its own scenario, when it is the same scan as the
  not-deployed scenario and so would produce byte-identical decisions.
"""

import pytest
import yaml

from src.dataset import controlled as C
from src.dataset.controlled import DOWN, SAME, UP, Scenario


def scenario(**kwargs):
    base = dict(name="s", image="nginx:1.21", description="d", expect=SAME,
                rationale="because", compare_to="baseline")
    return Scenario(**(base | kwargs))


class TestScenarioValidation:
    """Every rejection here is a session that does not get wasted."""

    def test_unknown_direction_is_rejected(self):
        with pytest.raises(ValueError, match="expect must be one of"):
            scenario(expect="higher")

    def test_unknown_exempt_direction_is_rejected(self):
        with pytest.raises(ValueError, match="exempt_expect must be one of"):
            scenario(exempt_cves=["CVE-2021-41773"], exempt_expect="maybe")

    def test_exposed_scenario_must_name_its_exposure_type(self):
        """Otherwise the manifest and the expectation can disagree silently."""
        with pytest.raises(ValueError, match="exposure_type"):
            scenario(exposed=True)

    def test_a_scenario_cannot_be_both_absent_and_exposed(self):
        with pytest.raises(ValueError, match="cannot also be exposed"):
            scenario(deployed=False, exposed=True, exposure_type="NodePort")

    def test_exempt_cves_must_differ_from_the_scenario_expectation(self):
        with pytest.raises(ValueError, match="pointless"):
            scenario(expect=DOWN, exempt_cves=["CVE-2021-41773"], exempt_expect=DOWN)

    def test_rationale_is_mandatory(self):
        """A scenario with no recorded reasoning cannot be defended in review."""
        with pytest.raises(ValueError, match="record why"):
            scenario(rationale="")

    def test_is_reference_detects_self_comparison(self):
        assert scenario(name="baseline", compare_to="baseline").is_reference
        assert not scenario(name="other", compare_to="baseline").is_reference


class TestMatrixValidation:

    def write(self, tmp_path, entries):
        path = tmp_path / "scenarios.yaml"
        path.write_text(yaml.safe_dump({"scenarios": entries}), encoding="utf-8")
        return path

    def ref(self, name="baseline", image="nginx:1.21"):
        return dict(name=name, image=image, compare_to=name, description="d",
                    expect=SAME, rationale="r", deployed=True)

    def test_a_reference_is_required(self, tmp_path):
        path = self.write(tmp_path, [dict(name="a", image="nginx:1.21",
                                          compare_to="baseline", description="d",
                                          expect=UP, rationale="r")])
        with pytest.raises(ValueError, match="at least one reference"):
            C.load_scenarios(path)

    def test_reference_must_be_neutral(self, tmp_path):
        bad = self.ref() | {"exposed": True, "exposure_type": "NodePort"}
        path = self.write(tmp_path, [bad])
        with pytest.raises(ValueError, match="internal-only"):
            C.load_scenarios(path)

    def test_duplicate_names_are_rejected(self, tmp_path):
        path = self.write(tmp_path, [self.ref(), self.ref()])
        with pytest.raises(ValueError, match="duplicate"):
            C.load_scenarios(path)

    def test_comparison_across_images_is_rejected(self, tmp_path):
        """
        The flaw this catches: an httpd scenario compared against an nginx reference
        shares almost no CVEs, so the few that overlap would be scored as a context
        effect rather than as an artefact of two different package sets.
        """
        entries = [self.ref(),
                   dict(name="x", image="httpd:2.4.49", compare_to="baseline",
                        description="d", expect=DOWN, rationale="r", deployed=False)]
        path = self.write(tmp_path, entries)
        with pytest.raises(ValueError, match="same-image"):
            C.load_scenarios(path)

    def test_comparison_to_a_nonreference_is_rejected(self, tmp_path):
        entries = [self.ref(),
                   dict(name="mid", image="nginx:1.21", compare_to="baseline",
                        description="d", expect=UP, rationale="r"),
                   dict(name="leaf", image="nginx:1.21", compare_to="mid",
                        description="d", expect=UP, rationale="r")]
        path = self.write(tmp_path, entries)
        with pytest.raises(ValueError, match="not a reference"):
            C.load_scenarios(path)

    def test_comparison_to_an_unknown_scenario_is_rejected(self, tmp_path):
        entries = [self.ref(),
                   dict(name="x", image="nginx:1.21", compare_to="ghost",
                        description="d", expect=UP, rationale="r")]
        path = self.write(tmp_path, entries)
        with pytest.raises(ValueError, match="unknown scenario"):
            C.load_scenarios(path)

    def test_an_image_without_a_reference_is_rejected(self, tmp_path):
        entries = [self.ref(),
                   dict(name="py", image="python:3.9-slim", compare_to="baseline",
                        description="d", expect=SAME, rationale="r")]
        path = self.write(tmp_path, entries)
        with pytest.raises(ValueError, match="same-image|no reference"):
            C.load_scenarios(path)

    def test_a_missing_file_says_it_is_version_controlled(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="not generated"):
            C.load_scenarios(tmp_path / "absent.yaml")


class TestCommittedMatrix:
    """The real scenarios.yaml must stay loadable and coherent."""

    def test_it_loads(self):
        assert len(C.load_scenarios()) >= 8

    def test_every_image_has_a_reference(self):
        scenarios = C.load_scenarios()
        refs = {s.image for s in scenarios if s.is_reference}
        assert {s.image for s in scenarios} == refs

    def test_it_exercises_both_directions(self):
        """
        A matrix that only tested escalation would not test the bidirectional claim,
        which is one of the paper's three stated design properties.
        """
        expects = {s.expect for s in C.load_scenarios()}
        assert UP in expects and DOWN in expects

    def test_the_kev_exemption_is_tested_within_a_descalating_scenario(self):
        """
        It cannot be a scenario of its own: it would be the same scan as not-deployed
        and would score identically, testing nothing.
        """
        exempting = [s for s in C.load_scenarios()
                     if s.exempt_cves or s.exempt_when_kev]
        assert exempting, "no scenario tests a carve-out"
        for s in exempting:
            assert s.expect != s.exempt_expect

    def test_the_kev_carve_out_is_a_predicate_not_a_list_of_ids(self):
        """
        Naming CVE ids makes the test fragile and, worse, invites fitting: the first
        version listed two ids that Trivy does not report for httpd:2.4.49, and the
        tempting fix was to substitute whichever KEV id did appear. The property under
        test is KEV membership, so the scenario states that instead.
        """
        kev_scenarios = [s for s in C.load_scenarios() if s.exempt_when_kev]
        assert kev_scenarios, "the KEV exemption must be expressed as a predicate"
        for s in kev_scenarios:
            assert not s.exempt_cves, (
                f"{s.name} mixes a KEV predicate with hardcoded ids; keep one")

    def test_runtime_scenarios_cover_attributable_and_not(self):
        """
        The unattributable case is the more important one -- it is the property issue
        #17 was opened about -- so a matrix with only the positive case is incomplete.
        """
        runtime = [s for s in C.load_scenarios() if s.runtime_actions]
        attributed = [a for s in runtime for a in s.runtime_actions
                      if a.get("attributed_package")]
        unattributed = [a for s in runtime for a in s.runtime_actions
                        if not a.get("attributed_package")]
        assert attributed and unattributed


class TestRenderedManifests:

    def docs(self):
        rendered = C.render_manifests(C.load_scenarios())
        return [d for d in yaml.safe_load_all(rendered) if d]

    def test_every_document_is_valid_yaml_with_a_kind(self):
        for doc in self.docs():
            assert doc.get("kind"), doc
            assert doc.get("apiVersion"), doc

    def test_deployed_scenarios_produce_a_deployment(self):
        names = {d["metadata"]["name"] for d in self.docs()
                 if d["kind"] == "Deployment"}
        for s in C.load_scenarios():
            if s.deployed:
                assert s.workload_name in names
            else:
                assert s.workload_name not in names

    def test_exposed_scenarios_produce_a_matching_service(self):
        services = {d["metadata"]["name"]: d for d in self.docs()
                    if d["kind"] == "Service"}
        for s in C.load_scenarios():
            if s.exposed:
                assert services[s.workload_name]["spec"]["type"] == s.exposure_type
            else:
                assert s.workload_name not in services

    def test_privileged_scenarios_set_the_security_context(self):
        deployments = {d["metadata"]["name"]: d for d in self.docs()
                       if d["kind"] == "Deployment"}
        for s in C.load_scenarios():
            if not s.deployed:
                continue
            container = (deployments[s.workload_name]["spec"]["template"]["spec"]
                         ["containers"][0])
            got = container.get("securityContext", {}).get("privileged", False)
            assert got == s.privileged, s.name

    def test_selectors_match_the_pod_labels(self):
        """A mismatch here deploys pods no Service ever reaches, so nothing is exposed."""
        for d in self.docs():
            if d["kind"] != "Deployment":
                continue
            selector = d["spec"]["selector"]["matchLabels"]
            labels = d["spec"]["template"]["metadata"]["labels"]
            assert selector.items() <= labels.items()

    def test_a_namespace_is_created_for_every_scenario(self):
        created = {d["metadata"]["name"] for d in self.docs() if d["kind"] == "Namespace"}
        assert {s.namespace for s in C.load_scenarios()} <= created

    def test_command_override_is_rendered(self):
        deployments = {d["metadata"]["name"]: d for d in self.docs()
                       if d["kind"] == "Deployment"}
        for s in C.load_scenarios():
            if not s.deployed:
                continue
            container = (deployments[s.workload_name]["spec"]["template"]["spec"]
                         ["containers"][0])
            assert container.get("command", []) == list(s.command), s.name

    def test_non_server_images_are_given_a_long_running_command(self):
        """
        A pod that exits is not a scenario -- the deployment context under test is
        derived from *live* pods, so a container that completes immediately scores as
        "no findings" rather than as an error, which is the silent-failure shape.

        `python:3.9-slim` runs an interactive interpreter by default; with no TTY it
        reads EOF and exits 0, and Kubernetes reports "Completed", not a crash. Both
        python scenarios did exactly this on first deploy.
        """
        non_servers = ("python", "node", "openjdk", "golang", "ruby", "busybox",
                       "alpine", "debian", "ubuntu")
        for s in C.load_scenarios():
            if not s.deployed:
                continue
            base = s.image.split(":")[0].split("/")[-1]
            if base in non_servers:
                assert s.command, (
                    f"scenario {s.name!r} runs {s.image}, which does not stay up on its "
                    f"own; give it an explicit long-running command")

    def test_image_in_the_manifest_matches_the_scenario(self):
        deployments = {d["metadata"]["name"]: d for d in self.docs()
                       if d["kind"] == "Deployment"}
        for s in C.load_scenarios():
            if s.deployed:
                container = (deployments[s.workload_name]["spec"]["template"]["spec"]
                             ["containers"][0])
                assert container["image"] == s.image


class TestImageSharingRequiresIsolation:
    """
    Several scenarios deliberately share an image, and that is only safe because
    collection deploys one scenario at a time.

    `k8s_context.derive_context` resolves context by image and aggregates with `any()`
    across every matching pod. With the six nginx scenarios up simultaneously, each one
    observes `exposed=True` and `privileged=True` -- the union of all six -- so every
    scenario receives identical context and the comparison measures nothing.

    The failure is silent: the scans succeed and the decisions look plausible. These
    tests record the constraint so a future change to batch the deployment has to
    confront it.
    """

    def test_images_really_are_shared(self):
        images = [s.image for s in C.load_scenarios()]
        shared = {i for i in images if images.count(i) > 1}
        assert shared, ("if no image is shared this constraint has gone away and the "
                        "collect docstring should be revisited")

    def test_scenarios_sharing_an_image_differ_in_context(self):
        """Exactly why they cannot be observed at the same time."""
        by_image = {}
        for s in C.load_scenarios():
            by_image.setdefault(s.image, []).append(s)
        for image, group in by_image.items():
            if len(group) < 2:
                continue
            shapes = {(s.deployed, s.exposed, s.privileged) for s in group}
            assert len(shapes) > 1, (
                f"all scenarios on {image} have identical context; at least one pair "
                f"must differ or the image is not testing anything")

    def test_every_deployed_scenario_is_individually_renderable(self):
        """
        Collection renders one scenario at a time, so each must produce a complete,
        self-sufficient manifest -- namespace included.
        """
        import yaml as _yaml
        for s in C.load_scenarios():
            docs = [d for d in _yaml.safe_load_all(C.render_manifests([s])) if d]
            kinds = {d["kind"] for d in docs}
            assert "Namespace" in kinds, s.name
            if s.deployed:
                assert "Deployment" in kinds, s.name

    def test_scenario_labels_allow_targeted_teardown(self):
        """
        Teardown selects on `scenario=<name>`. Without that label on every object,
        deleting one scenario would either miss objects or take out its neighbours.
        """
        import yaml as _yaml
        for s in C.load_scenarios():
            for d in _yaml.safe_load_all(C.render_manifests([s])):
                if not d or d["kind"] not in ("Deployment", "Service"):
                    continue
                assert d["metadata"]["labels"].get("scenario") == s.name


class TestDirection:

    @pytest.mark.parametrize("before,after,expected", [
        ("HIGH", "CRITICAL", UP), ("CRITICAL", "HIGH", DOWN), ("HIGH", "HIGH", SAME),
        ("LOW", "CRITICAL", UP), ("CRITICAL", "LOW", DOWN),
    ])
    def test_direction_between(self, before, after, expected):
        assert C.direction_between(before, after) == expected

    def test_unknown_priorities_do_not_invent_a_direction(self):
        assert C.direction_between("WAT", "CRITICAL") == SAME


class TestScoring:

    REF = {"CVE-1": "HIGH", "CVE-2": "HIGH", "CVE-3": "MEDIUM"}

    def test_counts_agreement_with_the_expected_direction(self):
        s = scenario(name="x", expect=UP)
        r = C.score(self.REF, {"CVE-1": "CRITICAL", "CVE-2": "HIGH",
                               "CVE-3": "HIGH"}, s)
        assert r["findings_compared"] == 3
        assert r["moved_as_expected"] == 2
        assert r["unchanged"] == 1
        assert r["wrong_direction"] == 0

    def test_movement_the_wrong_way_is_counted_separately_from_no_movement(self):
        s = scenario(name="x", expect=UP)
        r = C.score(self.REF, {"CVE-1": "LOW", "CVE-2": "HIGH", "CVE-3": "HIGH"}, s)
        assert r["wrong_direction"] == 1
        assert r["unchanged"] == 1
        assert r["moved_as_expected"] == 1

    def test_only_shared_findings_are_scored(self):
        """A CVE in one scan and not the other is scanner variance, not a context effect."""
        s = scenario(name="x", expect=UP)
        r = C.score(self.REF, {"CVE-1": "CRITICAL", "CVE-99": "CRITICAL"}, s)
        assert r["findings_compared"] == 1

    def test_exempt_cves_are_scored_against_their_own_expectation(self):
        s = scenario(name="x", expect=DOWN, exempt_cves=["CVE-2"], exempt_expect=SAME)
        r = C.score(self.REF, {"CVE-1": "LOW", "CVE-2": "HIGH", "CVE-3": "LOW"}, s)
        assert r["findings_compared"] == 2          # CVE-2 excluded from the main bucket
        assert r["moved_as_expected"] == 2
        assert r["exempt_findings_compared"] == 1
        assert r["exempt_moved_as_expected"] == 1

    def test_a_failed_exemption_is_visible_rather_than_averaged_away(self):
        """
        With the exemption folded into the main bucket, a total failure of the carve-out
        would move the headline rate by one finding in hundreds.
        """
        s = scenario(name="x", expect=DOWN, exempt_cves=["CVE-2"], exempt_expect=SAME)
        r = C.score(self.REF, {"CVE-1": "LOW", "CVE-2": "LOW", "CVE-3": "LOW"}, s)
        assert r["exempt_agreement_rate"] == 0.0
        assert r["exempt_wrong_direction"] == 1

    def test_kev_predicate_selects_the_exempt_bucket_from_the_scan(self):
        """The carve-out is derived from what the scan found, not from a fixed list."""
        s = scenario(name="x", expect=DOWN, exempt_when_kev=True, exempt_expect=SAME)
        r = C.score(self.REF, {"CVE-1": "LOW", "CVE-2": "HIGH", "CVE-3": "LOW"}, s,
                    kev_cves={"CVE-2"})
        assert r["findings_compared"] == 2
        assert r["moved_as_expected"] == 2
        assert r["exempt_findings_compared"] == 1
        assert r["exempt_moved_as_expected"] == 1

    def test_no_kev_findings_means_an_empty_exempt_bucket(self):
        s = scenario(name="x", expect=DOWN, exempt_when_kev=True, exempt_expect=SAME)
        r = C.score(self.REF, {"CVE-1": "LOW"}, s, kev_cves=set())
        assert r["exempt_findings_compared"] == 0
        assert r["exempt_agreement_rate"] is None

    def test_movable_excludes_findings_already_at_the_ladder_bound(self):
        """
        359 of nginx's 560 findings are already Track; no escalation rule will move
        them, so counting them as failures measures the image, not the method.
        """
        ref = {"a": "CRITICAL", "b": "HIGH", "c": "LOW"}
        got = {"a": "CRITICAL", "b": "CRITICAL", "c": "LOW"}
        up = C.score(ref, got, scenario(name="x", expect=UP))
        assert up["findings_compared"] == 3
        assert up["movable"] == 2            # the CRITICAL cannot rise
        assert up["moved_as_expected"] == 1
        assert up["movable_agreement_rate"] == 0.5

        down = C.score(ref, {"a": "HIGH", "b": "HIGH", "c": "LOW"},
                       scenario(name="y", expect=DOWN))
        assert down["movable"] == 2          # the LOW cannot fall
        assert down["movable_agreement_rate"] == 0.5

    def test_movable_rate_is_none_when_nothing_could_move(self):
        ref = {"a": "CRITICAL"}
        r = C.score(ref, {"a": "CRITICAL"}, scenario(name="x", expect=UP))
        assert r["movable"] == 0
        assert r["movable_agreement_rate"] is None

    @pytest.mark.parametrize("priority,direction,expected", [
        ("CRITICAL", UP, False), ("HIGH", UP, True),
        ("LOW", DOWN, False), ("MEDIUM", DOWN, True),
        ("HIGH", SAME, True), ("WAT", UP, False),
    ])
    def test_movable(self, priority, direction, expected):
        assert C.movable(priority, direction) is expected

    def test_missing_exempt_cves_are_reported(self):
        s = scenario(name="x", expect=DOWN, exempt_cves=["CVE-404"], exempt_expect=SAME)
        r = C.score(self.REF, {"CVE-1": "LOW"}, s)
        assert r["exempt_cves_missing"] == ["CVE-404"]

    def test_empty_overlap_yields_no_rate_rather_than_zero(self):
        """Zero would read as total failure; None reads as 'nothing was measured'."""
        s = scenario(name="x", expect=UP)
        r = C.score(self.REF, {}, s)
        assert r["agreement_rate"] is None
