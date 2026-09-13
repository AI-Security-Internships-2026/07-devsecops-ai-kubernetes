"""
K-CAVP decision thresholds — the single place every numeric cut-off is defined.

Why this module exists
----------------------
Two separate requirements land on the same problem. Reviewers asked on what basis the
EPSS and CVSS thresholds were chosen (issue #19 item 7, issue #26), and the threshold
sensitivity sweep (issue #24, experiment 6D) has to vary them without editing source.
Both need the thresholds in one documented, overridable place.

Provenance is recorded alongside each value, and it is deliberately honest: two of the
five thresholds come from published sources, and three are our own engineering choices
that are justified empirically by the 6D sweep rather than by citation. `PROVENANCE`
below is the authoritative record and the paper's threshold table is generated from it,
so the table cannot drift from the code.

Overriding for a sweep
----------------------
Every field can be overridden by an environment variable, so a sweep is a loop over
values rather than a series of edits:

    K_CAVP_EPSS_ACT=0.05 python run.py pipeline nginx:1.21

Or programmatically, which is what the evaluation runner does:

    base = Thresholds()
    for t in (0.01, 0.025, 0.05, 0.075, 0.10, 0.15, 0.20):
        variant = base.replace(epss_act=t)
"""

import os
from dataclasses import dataclass, fields, replace

# Falco alert priorities that are severe enough to be *eligible* to escalate a finding.
# Falco's own priority vocabulary, most severe first; everything below Error annotates
# but never changes a decision.
FALCO_CRITICAL_TIER = frozenset({"EMERGENCY", "ALERT", "CRITICAL", "ERROR"})

# Ordinal priority ladder, lowest to highest. Kept here rather than in ssvc.py so the
# bound in `max_escalation_levels` is interpretable against a single definition.
LADDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class Thresholds:
    """
    Every numeric cut-off in the decision engine.

    Frozen so a threshold set is a value, not mutable global state: the sweep holds
    several at once and a run cannot silently mutate the one it was given.
    """

    # --- base classification -------------------------------------------------
    epss_act: float = 0.10
    """EPSS at or above which a finding is Act (CRITICAL) on predictive signal alone."""

    epss_attend: float = 0.01
    """EPSS at or above which a finding is at least Track* (MEDIUM)."""

    cvss_high: float = 7.0
    """CVSS base score at or above which severity counts as High for the Attend rule."""

    # --- contextual refinement ----------------------------------------------
    epss_context_escalate: float = 0.05
    """Minimum EPSS for deployment context (exposed/privileged) to escalate a HIGH."""

    epss_context_deescalate: float = 0.20
    """
    EPSS below which a non-KEV CRITICAL on an internal, unprivileged pod is
    de-escalated. Above this the finding is considered exploitable enough that
    deployment context should not reduce it.
    """

    # --- bound ---------------------------------------------------------------
    max_escalation_levels: int = 1
    """
    Maximum number of ladder levels the refinements may raise a finding above its base
    classification, in aggregate. Experiment 6B varies this (0, 1, 2, unbounded) to
    justify the default by evidence rather than by the defects it was introduced to
    prevent.
    """

    def replace(self, **changes) -> "Thresholds":
        """Return a copy with fields overridden — the sweep's primary entry point."""
        unknown = set(changes) - {f.name for f in fields(self)}
        if unknown:
            raise ValueError(f"unknown threshold(s): {', '.join(sorted(unknown))}")
        return replace(self, **changes)

    def as_dict(self) -> dict:
        """Flat mapping, for recording the exact threshold set alongside a result."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_env(cls, env=None) -> "Thresholds":
        """
        Build from K_CAVP_<FIELD> environment variables, falling back to the defaults.

        A malformed value is a configuration error and raises, rather than silently
        falling back — a sweep that quietly used the default would produce results
        labelled with a threshold it never applied.
        """
        env = os.environ if env is None else env
        values = {}
        for f in fields(cls):
            raw = env.get(f"K_CAVP_{f.name.upper()}")
            if raw is None or raw.strip() == "":
                continue
            try:
                values[f.name] = int(raw) if f.type is int or f.type == "int" else float(raw)
            except ValueError as e:
                raise ValueError(
                    f"K_CAVP_{f.name.upper()}={raw!r} is not a valid "
                    f"{'integer' if f.type in (int, 'int') else 'number'}"
                ) from e
        return cls(**values)


# Default set, used unless a caller passes its own.
DEFAULTS = Thresholds()


# ---------------------------------------------------------------------------
# Provenance. `basis` distinguishes a threshold we can cite from one we chose.
#
#   "published"  - defined by an external specification or reported in the
#                  literature as an operating point. Cite it.
#   "internal"   - our engineering choice. NOT citable; must be justified by the
#                  threshold sensitivity sweep (issue #24, experiment 6D).
#
# The paper's threshold table is generated from this, so a threshold cannot appear in
# the paper without its basis stated.
# ---------------------------------------------------------------------------
PROVENANCE = {
    "epss_act": {
        "basis": "published",
        "source": "Jacobs et al., EPSS v3 (arXiv:2302.14172); FIRST EPSS guidance",
        "note": "EPSS >= 0.1 is the widely used operating point; reported as covering "
                "the majority of exploited vulnerabilities while flagging a small "
                "fraction of the population. Also the threshold our EPSS-only baseline "
                "uses, so the comparison shares one operating point by construction.",
    },
    "cvss_high": {
        "basis": "published",
        "source": "CVSS v3.1 specification, qualitative severity rating scale (FIRST)",
        "note": "7.0-8.9 is defined as 'High' by the specification itself, so this is a "
                "standards definition rather than a tuned parameter. Also the threshold "
                "our CVSS-only baseline uses.",
    },
    "epss_attend": {
        "basis": "internal",
        "source": None,
        "note": "Chosen to separate 'some measurable exploit probability' from "
                "negligible. No published basis; justified by the 6D sweep.",
    },
    "epss_context_escalate": {
        "basis": "internal",
        "source": None,
        "note": "Requires a finding to be genuinely exploitable before exposure or "
                "privilege may raise it, so context re-ranks rather than manufactures "
                "urgency. No published basis; justified by the 6D sweep.",
    },
    "epss_context_deescalate": {
        "basis": "internal",
        "source": None,
        "note": "Bounds the noise-reduction rule to borderline criticals. No published "
                "basis; justified by the 6D sweep.",
    },
    "max_escalation_levels": {
        "basis": "internal",
        "source": None,
        "note": "Introduced after two defects allowed refinements to compound. That is "
                "an engineering motivation, not evidence; experiment 6B compares 0/1/2/"
                "unbounded to justify the value on results.",
    },
}


def provenance_rows() -> list[dict]:
    """
    Threshold provenance as table rows, for the paper and for `run.py thresholds`.

    Ordered published-first so the citable thresholds — the ones that define the
    actionable boundary and are shared with the baselines — read before our own.
    """
    d = DEFAULTS.as_dict()
    rows = [
        {
            "threshold": name,
            "value": d[name],
            "basis": meta["basis"],
            "source": meta["source"] or "this work",
            "note": meta["note"],
        }
        for name, meta in PROVENANCE.items()
    ]
    rows.sort(key=lambda r: (r["basis"] != "published", r["threshold"]))
    return rows
