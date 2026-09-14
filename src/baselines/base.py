"""
Common contract every prioritization method implements (issue #20).

The comparison is only fair if every method sees identical records and returns
identically-shaped results, so the schema lives here rather than in each baseline. A
method that quietly consumed a different field, or ranked on a different scale, would
produce a difference that looks like a finding and is actually an artefact.

Two properties are load-bearing:

**Determinism.** Ranking ties are broken on a fixed key, so the same input always yields
the same order. Without that, Precision@K silently varies between runs and any measured
difference at small K is partly noise.

**No threshold tuning on test outcomes.** Thresholds are parameters supplied by the
caller, never fitted inside a method. The sweep in issue #24 varies them explicitly; a
method that picked its own optimum would be reporting its best case, not its behaviour.
"""

from dataclasses import dataclass, field


# Decision vocabulary shared by every method. Binary at this level: the research question
# is "would an analyst have looked at this?", and a four-tier scale is only meaningful for
# methods that produce one. K-CAVP's own tiers are preserved separately in `priority`.
ACTIONABLE = "actionable"
NOT_ACTIONABLE = "non-actionable"


@dataclass
class Decision:
    """One method's verdict on one finding."""

    cve_id: str
    method: str
    score: float
    decision: str
    explanation: str
    # Assigned by `rank_decisions` once the whole set is known, so it stays consistent
    # with the ordering actually used for Precision@K.
    rank: int = 0
    # K-CAVP emits Act/Attend/Track*/Track; baselines leave this empty. Kept so ordinal
    # methods are not flattened to binary in the stored results.
    priority: str = ""
    signals: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "method": self.method,
            "score": round(self.score, 6),
            "decision": self.decision,
            "rank": self.rank,
            "priority": self.priority,
            "explanation": self.explanation,
            **{f"signal_{k}": v for k, v in self.signals.items()},
        }


def as_bool(value) -> bool:
    """
    Coerce a CSV field to bool.

    The dataset round-trips through CSV, where `False` is the string "False" — which is
    truthy. Every method reads the same fields, so one loose coercion would corrupt all
    of them identically and invisibly.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def rank_decisions(decisions: list[Decision]) -> list[Decision]:
    """
    Assign ranks by descending score, breaking ties deterministically.

    Ties are broken by CVE id — arbitrary, but *stable*, which is what Precision@K needs.
    Ranking by score alone would leave the order of equal-scored findings up to sort
    stability and input order, so a rerun on reordered input would move items across the
    K boundary and change the metric.
    """
    ordered = sorted(decisions, key=lambda d: (-d.score, d.cve_id))
    for i, d in enumerate(ordered, start=1):
        d.rank = i
    return ordered


class Baseline:
    """
    Interface for a prioritization method.

    Subclasses implement `decide` for a single record; `run` handles the set and the
    ranking so no method can accidentally define its own ordering.
    """

    name: str = "base"
    description: str = ""
    # For Table B1 / Figure B1 — which signals the method actually consumes. Declared
    # rather than inferred, so the coverage matrix in the paper is generated from the
    # code instead of being maintained by hand alongside it.
    uses_signals: tuple[str, ...] = ()

    def decide(self, record: dict) -> Decision:
        raise NotImplementedError

    def run(self, records: list[dict]) -> list[Decision]:
        return rank_decisions([self.decide(r) for r in records])

    def actionable_count(self, decisions: list[Decision]) -> int:
        return sum(1 for d in decisions if d.decision == ACTIONABLE)


# Every signal a method could use. Order is the presentation order for Figure B1.
ALL_SIGNALS = (
    "cvss_severity",
    "epss",
    "kev",
    "public_exploit",
    "k8s_deployed",
    "k8s_exposure",
    "k8s_privilege",
    "runtime_evidence",
)
