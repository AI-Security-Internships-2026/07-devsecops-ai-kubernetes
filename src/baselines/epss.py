"""Baseline B — EPSS-only threshold policy (issue #20)."""

from src.baselines.base import ACTIONABLE, NOT_ACTIONABLE, Baseline, Decision, as_float
from src.triage.thresholds import DEFAULTS


class EpssOnly(Baseline):
    """
    Act above an EPSS threshold. The strongest single-signal baseline in the literature,
    and the one our method has to beat on something other than raw volume.

    The threshold is a constructor parameter because issue #24's sweep varies it across
    0.01-0.20; it is never fitted to the outcome labels inside this class.
    """

    name = "epss_only"
    description = "EPSS >= threshold (default 0.10, the commonly cited operating point)"
    uses_signals = ("epss",)

    def __init__(self, threshold: float | None = None):
        self.threshold = DEFAULTS.epss_act if threshold is None else threshold

    def decide(self, record: dict) -> Decision:
        epss = as_float(record.get("epss_score"))
        hit = epss >= self.threshold
        return Decision(
            cve_id=record["cve_id"],
            method=self.name,
            score=epss,
            decision=ACTIONABLE if hit else NOT_ACTIONABLE,
            explanation=f"EPSS {epss:.5f} {'>=' if hit else '<'} threshold {self.threshold}",
            signals={"epss": epss},
        )
