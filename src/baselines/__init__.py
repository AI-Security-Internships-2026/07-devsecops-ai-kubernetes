"""
Prioritization baselines for the publication comparison (issue #20).

Every method implements the same interface and consumes identical records, so a
difference in results is a difference in method rather than in plumbing.

    from src.baselines import build_baselines
    for name, method in build_baselines().items():
        decisions = method.run(records)
"""

from src.baselines.base import (ACTIONABLE, ALL_SIGNALS, NOT_ACTIONABLE, Baseline,
                                Decision, rank_decisions)
from src.baselines.chaining import DeterministicChaining
from src.baselines.cvss import CvssOnly
from src.baselines.epss import EpssOnly
from src.baselines.kev_epss import KevThenEpss
from src.baselines.official_ssvc import OfficialSSVC

# Ordered weakest to strongest, which is also the order Table B1 should read.
BASELINE_CLASSES = (CvssOnly, EpssOnly, KevThenEpss, OfficialSSVC, DeterministicChaining)


def build_baselines(**overrides) -> dict[str, Baseline]:
    """
    Instantiate every baseline with default parameters.

    `overrides` maps a baseline name to constructor kwargs, which is how the threshold
    sweep varies one method without disturbing the others:

        build_baselines(epss_only={"threshold": 0.05})
    """
    out = {}
    for cls in BASELINE_CLASSES:
        kwargs = overrides.get(cls.name, {})
        out[cls.name] = cls(**kwargs)
    return out


def signal_matrix() -> list[dict]:
    """
    Rows for Figure B1 — which signals each method consumes.

    Generated from each class's declared `uses_signals` so the figure cannot drift from
    the implementations it describes.
    """
    rows = []
    for cls in BASELINE_CLASSES:
        rows.append({"method": cls.name,
                     **{s: (s in cls.uses_signals) for s in ALL_SIGNALS}})
    return rows


__all__ = [
    "ACTIONABLE", "NOT_ACTIONABLE", "ALL_SIGNALS", "Baseline", "Decision",
    "rank_decisions", "CvssOnly", "EpssOnly", "KevThenEpss", "OfficialSSVC",
    "DeterministicChaining", "BASELINE_CLASSES", "build_baselines", "signal_matrix",
]
