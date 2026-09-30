"""
Rung L0 of the noise-reduction ladder — no prioritization at all (issue #26).

This is not a competing method. It is the *denominator*: the queue an operator faces
when the scanner output is handed over untriaged. Every reduction percentage reported
anywhere in the paper is measured against this, so it deserves to exist as a real
object that runs through the same harness rather than as a number written by hand into
a table.

Ranking is deliberately uninformative: every finding scores 0.0, so the order is the
deterministic tie-break on unit id and carries no signal. Precision@K for this rung is
therefore an arbitrary-order sample and must be reported as such, never as evidence
that unprioritized output ranks badly -- it does not rank at all.
"""

from src.baselines.base import ACTIONABLE, Baseline, Decision


class ScanOnly(Baseline):
    """Everything the scanner reports is actionable."""

    name = "scan_only"
    description = "No prioritization: every scanner finding enters the queue"
    uses_signals = ()

    def decide(self, record: dict) -> Decision:
        return Decision(
            cve_id=record["cve_id"],
            method=self.name,
            score=0.0,
            decision=ACTIONABLE,
            explanation="no prioritization applied; finding enters the queue",
            signals={},
        )
