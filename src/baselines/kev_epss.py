"""Baseline C — KEV first, then EPSS (issue #20)."""

from src.baselines.base import (ACTIONABLE, NOT_ACTIONABLE, Baseline, Decision,
                                as_bool, as_float)
from src.triage.thresholds import DEFAULTS


class KevThenEpss(Baseline):
    """
    Confirmed exploitation overrides everything; otherwise fall back to an EPSS
    threshold. This is the obvious practitioner heuristic, and it is the baseline that
    matters most for our contribution claim: it already combines threat intelligence with
    exploit prediction, so anything K-CAVP adds has to be visible *beyond* this, not
    merely beyond CVSS.

    KEV items are scored above the EPSS range (1.0 + epss) so they rank first among
    themselves by EPSS, rather than being flattened to a single value.
    """

    name = "kev_epss"
    description = "Actionable if in CISA KEV, else EPSS >= threshold"
    uses_signals = ("kev", "epss")

    def __init__(self, threshold: float | None = None):
        self.threshold = DEFAULTS.epss_act if threshold is None else threshold

    def decide(self, record: dict) -> Decision:
        epss = as_float(record.get("epss_score"))
        in_kev = as_bool(record.get("kev_at_snapshot"))
        if in_kev:
            return Decision(
                cve_id=record["cve_id"], method=self.name, score=1.0 + epss,
                decision=ACTIONABLE,
                explanation="in CISA KEV at snapshot (confirmed exploitation)",
                signals={"kev": True, "epss": epss})
        hit = epss >= self.threshold
        return Decision(
            cve_id=record["cve_id"], method=self.name, score=epss,
            decision=ACTIONABLE if hit else NOT_ACTIONABLE,
            explanation=f"not in KEV; EPSS {epss:.5f} "
                        f"{'>=' if hit else '<'} threshold {self.threshold}",
            signals={"kev": False, "epss": epss})
