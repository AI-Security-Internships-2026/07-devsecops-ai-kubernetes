"""Baseline A — CVSS-only severity policy (issue #20)."""

from src.baselines.base import ACTIONABLE, NOT_ACTIONABLE, Baseline, Decision, as_float
from src.triage.thresholds import DEFAULTS


class CvssOnly(Baseline):
    """
    "Patch High and above" — the most common policy in practice, and the one the
    literature reports as highly inefficient (it flags a large share of the population
    to catch a modest share of exploited vulnerabilities).

    Ranks on the raw base score so the ordering is finer than the binary decision, which
    lets Precision@K distinguish a 9.8 from a 7.0 even though both are "actionable".
    """

    name = "cvss_only"
    description = "CVSS base score >= threshold (default 7.0, the v3.1 'High' boundary)"
    uses_signals = ("cvss_severity",)

    def __init__(self, threshold: float | None = None):
        self.threshold = DEFAULTS.cvss_high if threshold is None else threshold

    def decide(self, record: dict) -> Decision:
        score = as_float(record.get("cvss_score"))
        severity = (record.get("cvss_severity") or "").upper()
        # Severity is honoured as well as the numeric score: some records carry a
        # qualitative rating with a 0.0 score (no CVSS vector published), and dropping
        # those would understate the baseline rather than testing it fairly.
        hit = score >= self.threshold or severity in ("HIGH", "CRITICAL")
        return Decision(
            cve_id=record["cve_id"],
            method=self.name,
            score=score,
            decision=ACTIONABLE if hit else NOT_ACTIONABLE,
            explanation=(f"CVSS {score} ({severity or 'no severity'}) "
                         f"{'>=' if hit else '<'} threshold {self.threshold}"),
            signals={"cvss_score": score, "cvss_severity": severity},
        )
