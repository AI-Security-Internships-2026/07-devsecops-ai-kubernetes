"""
The proposed method, K-CAVP, as a comparison method (issues #20, #23).

Wrapping our own engine in the baseline interface is what makes the comparison honest:
every method then consumes identical records, is ranked by one implementation, and is
measured by one metrics module. A method that scored itself could score itself
differently.

What this can and cannot show on the historical dataset
-------------------------------------------------------
K-CAVP's distinguishing signals are Kubernetes deployment context and container runtime
behaviour. **The historical dataset has neither** — it is CVE-level records with no
cluster attached. So on Dataset A this runs as the *context-free* variant: base
classification plus the public-exploit refinement, with the escalation bound applied.

That is not a weakness to hide, it is the honest scope of what a CVE-level benchmark can
measure, and it is exactly the `Base + Exploit` row of the ablation in issue #23. The
context and runtime contributions require the controlled Kubernetes dataset (Dataset B)
and are measured there, not here.

Ablation support
----------------
`enable_*` flags switch each component off so the same class produces every ablation
variant, rather than a separate implementation per variant that could drift from the one
under test.
"""

from src.baselines.base import ACTIONABLE, NOT_ACTIONABLE, Baseline, Decision, as_bool
from src.triage import ssvc
from src.triage.thresholds import DEFAULTS, Thresholds

# Act and Attend are the actionable tiers: both mean an analyst looks at the finding,
# which is the question every other method is answering with its binary decision.
ACTIONABLE_PRIORITIES = ("CRITICAL", "HIGH")

# Ordering within the actionable set, so Precision@K can distinguish an Act from an
# Attend rather than treating the tiers as a single blob.
_PRIORITY_RANK = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.0}


class KCAVP(Baseline):
    """
    Kubernetes Context-Aware Vulnerability Prioritization.

    Deliberately named K-CAVP rather than SSVC: it uses SSVC's decision vocabulary
    (Act / Attend / Track* / Track) but not the official Deployer decision table, which
    is implemented separately as `OfficialSSVC`.
    """

    name = "kcavp"
    description = ("Proposed method: base classification + exploit, deployment context "
                   "and runtime refinements, bounded at one level")
    uses_signals = ("cvss_severity", "epss", "kev", "public_exploit",
                    "k8s_deployed", "k8s_exposure", "k8s_privilege", "runtime_evidence")

    def __init__(self, thresholds: Thresholds | None = None,
                 enable_kev: bool = True, enable_exploit: bool = True,
                 enable_context: bool = True, enable_runtime: bool = True,
                 enable_bound: bool = True, variant: str = "full",
                 mode: str | None = None):
        self.thresholds = thresholds or DEFAULTS
        if not enable_bound:
            # -1 disables the aggregate clamp, which is the "Full - Bound" ablation
            # variant issue #24 experiment 6B compares against.
            self.thresholds = self.thresholds.replace(max_escalation_levels=-1)
        # Off only for rung L3 of the noise ladder, which isolates what CVSS and EPSS
        # achieve before any confirmed-exploitation signal is added. Never off in the
        # deployed method.
        self.enable_kev = enable_kev
        self.enable_exploit = enable_exploit
        self.enable_context = enable_context
        self.enable_runtime = enable_runtime
        self.variant = variant
        # None leaves the engine to infer per record, which is what Dataset A needs
        # (it has no context and no runtime, so every record is pre-deployment).
        # Issue #24 sets it explicitly to compare the two rule sets.
        self.mode = mode

    def decide(self, record: dict) -> Decision:
        in_kev = (self.enable_kev
                  and (as_bool(record.get("kev_at_snapshot"))
                       or as_bool(record.get("in_kev"))))
        # The engine reads severity/epss/cvss under its own field names; the historical
        # dataset uses cvss_severity, so map rather than duplicate the parsing.
        cve = {
            "cve_id": record["cve_id"],
            "epss_score": _f(record.get("epss_score")),
            "cvss_score": _f(record.get("cvss_score")),
            "severity": record.get("cvss_severity") or record.get("severity") or "UNKNOWN",
            "in_kev": in_kev,
            "affected_packages": record.get("affected_packages") or [],
        }

        result = ssvc.analyze(
            cve, in_kev,
            context=record.get("k8s_context") if self.enable_context else None,
            exploit_exists=(self.enable_exploit
                            and as_bool(record.get("public_exploit_at_snapshot"))),
            runtime=record.get("runtime") if self.enable_runtime else None,
            thresholds=self.thresholds,
            mode=self.mode,
        )

        priority = result["priority"]
        actionable = priority in ACTIONABLE_PRIORITIES
        # Tier dominates the ranking; EPSS orders within a tier so the top of the queue
        # is still meaningfully sorted.
        score = _PRIORITY_RANK.get(priority, 0.0) + min(cve["epss_score"], 0.999)

        notes = result["notes"]
        return Decision(
            cve_id=record["cve_id"],
            method=self.name,
            score=score,
            decision=ACTIONABLE if actionable else NOT_ACTIONABLE,
            priority=result["decision"],          # Act / Attend / Track* / Track
            explanation="; ".join(notes) if notes else
                        f"base classification -> {result['decision']}",
            signals={"priority": priority, "variant": self.variant,
                     "mode": result["mode"], "notes": len(notes)},
        )


def _f(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# The six ablation variants issue #23 experiment 5B requires. Defined here so the
# evaluation runner cannot invent a seventh that was never specified.
ABLATION_VARIANTS = {
    "base": dict(enable_exploit=False, enable_context=False, enable_runtime=False),
    "base+exploit": dict(enable_exploit=True, enable_context=False, enable_runtime=False),
    "base+context": dict(enable_exploit=False, enable_context=True, enable_runtime=False),
    "full-minus-runtime": dict(enable_exploit=True, enable_context=True,
                               enable_runtime=False),
    "full-minus-bound": dict(enable_exploit=True, enable_context=True,
                             enable_runtime=True, enable_bound=False),
    "full": dict(enable_exploit=True, enable_context=True, enable_runtime=True),
}


def build_ablation(thresholds: Thresholds | None = None) -> dict[str, KCAVP]:
    """One K-CAVP instance per ablation variant, all sharing the same threshold set."""
    return {name: KCAVP(thresholds=thresholds, variant=name, **kwargs)
            for name, kwargs in ABLATION_VARIANTS.items()}
