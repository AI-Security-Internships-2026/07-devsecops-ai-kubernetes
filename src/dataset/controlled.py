"""
Dataset B -- controlled Kubernetes scenarios (issues #21, #24, #25).

Why a second dataset exists
---------------------------
Dataset A is a 933k-row historical corpus with temporal ground truth, and it answers RQ1
and RQ4 well. It cannot answer RQ2 or RQ3 at all, because it is CVE-level: there is no
cluster attached, so it carries no deployment state and no runtime behaviour. The
progressive ladder in `src.evaluation.ladder` makes this visible -- three of its rungs are
structurally flat on Dataset A.

Dataset B is the complement. It is small, constructed, and cluster-attached: the same
images and the same CVEs are deployed into deliberately different Kubernetes contexts, and
the *context* is the independent variable.

Ground truth here is constructed, not observed
----------------------------------------------
This is the important methodological point and the paper must state it plainly.

In Dataset A a label is an observation: a CVE either did or did not enter CISA KEV in the
window. Nobody decided it. In Dataset B we build the cluster, so the ground truth is the
scenario's *designed* reachability, asserted by us. That is legitimate for the questions
being asked -- RQ2 asks whether context moves a decision in the intended direction, and
RQ3 asks whether runtime evidence is attributed to the right package, both of which are
questions about the mechanism rather than about the world -- but it would be illegitimate
to present a Dataset B result as evidence about real-world exploitation rates, and we do
not.

Two consequences follow, and both are enforced here rather than left to discipline:

* Every scenario declares its expected decision *direction* relative to the same finding
  in the baseline scenario, not an absolute priority. An absolute expectation would be
  restating the implementation as the ground truth, and the test would pass by
  construction.
* Expected directions are written down before the run, in `scenarios.yaml`, and this
  module refuses to load a scenario that omits one.
"""

from dataclasses import dataclass, field
from pathlib import Path

from src import config

DATASET_B_DIR = config.ROOT / "experiments" / "dataset-b"
SCENARIOS_FILE = DATASET_B_DIR / "scenarios.yaml"

# The direction a scenario is expected to move a finding, relative to the same finding in
# the `baseline` scenario. Deliberately coarse: the claim under test is "context moves
# decisions the right way", not "context produces exactly this priority".
UP = "escalate"
DOWN = "de-escalate"
SAME = "unchanged"
DIRECTIONS = (UP, DOWN, SAME)

# Ordinal ladder, for turning two priorities into a direction.
_LADDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Scenario:
    """One deployed configuration of one image."""

    name: str
    image: str
    description: str
    expect: str
    # Which scenario this one is measured against. A scenario that names itself is a
    # reference point. The comparison must use the SAME IMAGE: comparing an httpd
    # scenario against an nginx reference would share almost no CVEs, and the handful
    # that did overlap would be scored as a context effect when they are an artefact of
    # two different package sets.
    compare_to: str = "baseline"
    # Kubernetes shape. These drive both the rendered manifests and the expected
    # context the pipeline should derive from the live cluster.
    deployed: bool = True
    exposed: bool = False
    exposure_type: str = ""          # NodePort | LoadBalancer | ""
    privileged: bool = False
    namespace: str = "dataset-b"
    replicas: int = 1
    # Overrides the image's default command. Needed for any image that is not a
    # long-running server: `python:3.9-slim` starts an interactive interpreter, which
    # reads EOF immediately and exits 0, so the pod reports "Completed" and never
    # becomes Ready. A scenario is only measurable while its pod is running, because the
    # deployment context being tested is derived from live pods.
    command: list[str] = field(default_factory=list)
    # CVEs that are expected to behave DIFFERENTLY from the rest of the scenario, with
    # the direction they should move instead. This is how the KEV exemption is tested:
    # in a not-deployed scenario every finding de-escalates except the confirmed-
    # exploited one. Modelling that as a separate scenario would not work -- it is the
    # same scan, so it would produce identical decisions and score identically.
    exempt_cves: list[str] = field(default_factory=list)
    exempt_expect: str = SAME
    # Runtime behaviour to provoke, for RQ3. Each entry names a package the behaviour
    # should be attributed to, so attribution precision has a labelled target.
    runtime_actions: list[dict] = field(default_factory=list)
    rationale: str = ""

    def __post_init__(self):
        for value, label in ((self.expect, "expect"),
                             (self.exempt_expect, "exempt_expect")):
            if value not in DIRECTIONS:
                raise ValueError(f"scenario {self.name!r}: {label} must be one of "
                                 f"{DIRECTIONS}, got {value!r}")
        if self.exposed and not self.exposure_type:
            raise ValueError(f"scenario {self.name!r}: exposed scenarios must name an "
                             f"exposure_type, so the manifest and the expectation agree")
        if not self.deployed and (self.exposed or self.privileged):
            raise ValueError(f"scenario {self.name!r}: a scenario that is not deployed "
                             f"cannot also be exposed or privileged")
        if self.exempt_cves and self.exempt_expect == self.expect:
            raise ValueError(f"scenario {self.name!r}: exempt_cves are pointless when "
                             f"exempt_expect equals expect")
        if not self.rationale:
            raise ValueError(f"scenario {self.name!r}: every scenario must record why "
                             f"the expected direction is what it is")

    @property
    def is_reference(self) -> bool:
        return self.compare_to == self.name

    @property
    def workload_name(self) -> str:
        return f"dsb-{self.name}".replace("_", "-").lower()

    def expected_context(self) -> dict:
        """
        The context the pipeline should derive from this scenario once deployed.

        Comparing this against what `k8s_context.get_context` actually returns is a
        check on the *context provider*, separate from the check on the decision engine.
        A scenario whose derived context is wrong would otherwise be scored as a
        decision failure.
        """
        if not self.deployed:
            return {"available": True, "deployed": False}
        return {
            "available": True,
            "deployed": True,
            "exposed": self.exposed,
            "exposure_type": self.exposure_type or None,
            "privileged": self.privileged,
        }


def direction_between(baseline_priority: str, observed_priority: str) -> str:
    """Which way `observed` moved relative to `baseline` on the priority ladder."""
    try:
        b, o = _LADDER.index(baseline_priority), _LADDER.index(observed_priority)
    except ValueError:
        return SAME
    if o > b:
        return UP
    if o < b:
        return DOWN
    return SAME


def load_scenarios(path: Path | None = None) -> list[Scenario]:
    """
    Read and validate the scenario matrix.

    Validation is strict on purpose. A scenario file is the experiment's pre-registration:
    a malformed entry silently dropped would change what the experiment tested without
    changing what it reported.
    """
    import yaml

    path = path or SCENARIOS_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Dataset B's scenario matrix is version-controlled; "
            f"it is not generated.")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = raw.get("scenarios") or []
    if not entries:
        raise ValueError(f"{path} declares no scenarios")

    scenarios = [Scenario(**entry) for entry in entries]

    names = [s.name for s in scenarios]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise ValueError(f"duplicate scenario name(s): {', '.join(sorted(duplicates))}")

    by_name = {s.name: s for s in scenarios}
    references = [s for s in scenarios if s.is_reference]
    if not references:
        raise ValueError(
            "at least one reference scenario is required (one whose compare_to is its "
            "own name); every expectation is expressed relative to one")

    for ref in references:
        if ref.expect != SAME:
            raise ValueError(f"reference scenario {ref.name!r} must expect 'unchanged' "
                             f"relative to itself")
        if ref.exposed or ref.privileged or not ref.deployed:
            raise ValueError(
                f"reference scenario {ref.name!r} must be deployed, internal-only and "
                f"unprivileged, so both escalation and de-escalation are measurable "
                f"from it")

    for s in scenarios:
        if s.is_reference:
            continue
        target = by_name.get(s.compare_to)
        if target is None:
            raise ValueError(f"scenario {s.name!r} compares to unknown scenario "
                             f"{s.compare_to!r}")
        if not target.is_reference:
            raise ValueError(f"scenario {s.name!r} compares to {s.compare_to!r}, which "
                             f"is not a reference scenario")
        if target.image != s.image:
            raise ValueError(
                f"scenario {s.name!r} runs {s.image} but compares to {s.compare_to!r} "
                f"which runs {target.image}. Comparisons must be same-image: two images "
                f"share almost no CVEs, so the overlap would be scored as a context "
                f"effect when it is an artefact of differing package sets.")

    # Every image that appears must have a reference, or its scenarios are unscoreable.
    ref_images = {s.image for s in references}
    orphans = sorted({s.image for s in scenarios} - ref_images)
    if orphans:
        raise ValueError(f"no reference scenario for image(s): {', '.join(orphans)}")

    return scenarios


def render_manifests(scenarios: list[Scenario]) -> str:
    """
    Kubernetes manifests for the whole matrix, as one multi-document YAML string.

    Rendering is separated from applying so the manifests can be reviewed, committed and
    diffed without a cluster. Applying them is the only step that needs the VM.
    """
    docs = [_namespace_doc(sorted({s.namespace for s in scenarios}))]
    for scenario in scenarios:
        if not scenario.deployed:
            # A not-deployed scenario is the *absence* of a workload, which is the
            # condition being tested. Emitting nothing is the correct rendering; a
            # comment records that the omission is deliberate.
            docs.append(f"# scenario '{scenario.name}': intentionally NOT deployed\n"
                        f"# {scenario.rationale}")
            continue
        docs.append(_deployment_doc(scenario))
        if scenario.exposed:
            docs.append(_service_doc(scenario))
    return "\n---\n".join(docs) + "\n"


def _namespace_doc(namespaces: list[str]) -> str:
    return "\n---\n".join(
        f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {ns}\n"
        f"  labels:\n    purpose: dataset-b" for ns in namespaces)


def _deployment_doc(s: Scenario) -> str:
    security = ("        securityContext:\n          privileged: true\n"
                if s.privileged else "")
    command = ""
    if s.command:
        rendered = ", ".join(f'"{part}"' for part in s.command)
        command = f"        command: [{rendered}]\n"
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {s.workload_name}
  namespace: {s.namespace}
  labels:
    app: {s.workload_name}
    scenario: {s.name}
  annotations:
    dataset-b/expect: "{s.expect}"
    dataset-b/rationale: "{s.rationale}"
spec:
  replicas: {s.replicas}
  selector:
    matchLabels:
      app: {s.workload_name}
  template:
    metadata:
      labels:
        app: {s.workload_name}
        scenario: {s.name}
    spec:
      containers:
      - name: app
        image: {s.image}
{command}{security}        resources:
          requests: {{cpu: 50m, memory: 64Mi}}
          limits: {{cpu: 500m, memory: 512Mi}}"""


def _service_doc(s: Scenario) -> str:
    return f"""apiVersion: v1
kind: Service
metadata:
  name: {s.workload_name}
  namespace: {s.namespace}
  labels:
    scenario: {s.name}
spec:
  type: {s.exposure_type}
  selector:
    app: {s.workload_name}
  ports:
  - port: 80
    targetPort: 80"""


def score(reference_decisions: dict, scenario_decisions: dict,
          scenario: Scenario) -> dict:
    """
    Score one scenario against its reference, per CVE.

    `*_decisions` map cve_id -> priority. Only CVEs present in both are scored: a finding
    that appears in one and not the other reflects a scan difference rather than a
    context effect, and counting it would attribute scanner noise to the method.

    Exempt CVEs are scored against `exempt_expect` and reported separately rather than
    folded into the headline rate. They are usually a handful of findings testing a
    specific carve-out -- the KEV exemption, for instance -- and averaging them into a
    population of hundreds would make a total failure of the carve-out invisible.
    """
    shared = sorted(set(reference_decisions) & set(scenario_decisions))
    exempt = {c.upper() for c in scenario.exempt_cves}

    buckets = {"main": {"expected": scenario.expect, "ids": []},
               "exempt": {"expected": scenario.exempt_expect, "ids": []}}
    for cve_id in shared:
        buckets["exempt" if cve_id.upper() in exempt else "main"]["ids"].append(cve_id)

    out = {"scenario": scenario.name, "compare_to": scenario.compare_to,
           "image": scenario.image, "per_cve": []}

    for label, bucket in buckets.items():
        agreed = wrong = flat = 0
        for cve_id in bucket["ids"]:
            before, after = reference_decisions[cve_id], scenario_decisions[cve_id]
            observed = direction_between(before, after)
            agrees = observed == bucket["expected"]
            if agrees:
                agreed += 1
            elif observed == SAME:
                flat += 1
            else:
                wrong += 1
            out["per_cve"].append({"cve_id": cve_id, "bucket": label,
                                   "reference": before, "observed": after,
                                   "direction": observed,
                                   "expected": bucket["expected"], "agrees": agrees})
        total = len(bucket["ids"])
        prefix = "" if label == "main" else "exempt_"
        out |= {
            f"{prefix}expected_direction": bucket["expected"],
            f"{prefix}findings_compared": total,
            f"{prefix}moved_as_expected": agreed,
            f"{prefix}wrong_direction": wrong,
            f"{prefix}unchanged": flat,
            # Reported as a rate, but the denominator travels with it: these scenarios
            # have tens of findings, not thousands.
            f"{prefix}agreement_rate": (agreed / total) if total else None,
        }

    # A CVE named as exempt but absent from the scan means the scenario is not testing
    # what it claims to. Surfaced rather than silently scored as zero findings.
    out["exempt_cves_missing"] = sorted(exempt - {c.upper() for c in shared})
    return out
