"""
Progressive noise-reduction ladder (issue #26, review request from the research reviewer).

The question this answers
------------------------
The main comparison shows where K-CAVP lands against independent baselines. It does not
show *what each layer of the method contributes*. A reviewer looking at a single
"81.0% reduction" figure cannot tell whether that came from the EPSS threshold doing all
the work, or from the fusion, or from the Kubernetes context.

This module answers that directly: start from the untriaged scanner queue and switch on
one signal layer at a time, reporting at every rung how much of the queue was removed
and how much recall was paid for it.

How it differs from the component ablation
------------------------------------------
`src.baselines.kcavp.ABLATION_VARIANTS` removes one component at a time from the full
method (leave-one-out) to show that each is load-bearing. The ladder builds the method
up from nothing (leave-one-in) to show the *shape of the reduction curve*. They answer
different questions and both belong in the paper.

Reading the rungs
-----------------
L0 is the denominator -- the queue with no prioritization. L1 and L2 are single-signal
policies and are alternatives to each other, not steps: both are measured against L0.
From L3 onward each rung strictly contains the one before it, so its delta is the
marginal contribution of exactly one added signal.

What this ladder can and cannot show on Dataset A
-------------------------------------------------
Two rungs are inert on the historical CVE-level dataset and it is important that this
is stated rather than discovered:

* **L4 (+KEV) equals L3 by construction.** The temporal protocol excludes any CVE
  already in KEV at the snapshot, because its exploitation was an input rather than a
  prediction. Every eligible row therefore has `kev_at_snapshot = False` and the KEV
  branch cannot fire. This is the same effect that makes the `kev_epss` baseline
  identical to `epss_only`, and it says nothing about KEV's value for triage *today* --
  only that KEV cannot contribute to *forecasting*.

* **L6 (+Kubernetes context) and L7 (+runtime) equal L5.** Dataset A has no cluster
  attached, so it carries no deployment or runtime columns at all. These rungs are
  measured on Dataset B and are reported here as structurally unmeasurable, not as
  zero-valued.

Reporting a flat tail honestly is the point. A ladder that showed gains at every rung on
a dataset that cannot carry those signals would be measuring an artefact.
"""

from dataclasses import dataclass

from src.baselines.base import Baseline
from src.baselines.cvss import CvssOnly
from src.baselines.epss import EpssOnly
from src.baselines.kcavp import KCAVP
from src.baselines.scan_only import ScanOnly
from src.triage.thresholds import Thresholds

# Reason codes for a rung that cannot move on a given dataset. Recorded per rung so the
# generated table carries the explanation with the number.
INERT_PROTOCOL = ("excluded by the temporal protocol: no eligible row is in KEV at the "
                  "snapshot, so this branch cannot fire")
INERT_NO_SIGNAL = ("signal absent from this dataset: CVE-level records carry no cluster "
                   "or runtime state")


@dataclass(frozen=True)
class Rung:
    """One step of the ladder."""

    key: str
    label: str
    adds: str
    stage: str
    compare_to: str | None
    cumulative: bool = True
    inert_on_cve_level: str = ""
    notes: str = ""


# The ladder. Order is the order the table reads.
#
# L1 and L2 are marked non-cumulative: they are the two single-signal policies, shown
# side by side against L0 so the reader can see what each score achieves alone before
# the fusion rung. The cumulative chain is L0 -> L3 -> L4 -> L5 -> L6 -> L7.
RUNGS: tuple[Rung, ...] = (
    Rung("L0", "Scan only (no triage)", "--", "Untriaged", None, cumulative=False,
         notes="the denominator for every reduction figure in the paper"),
    Rung("L1", "CVSS only", "severity", "Single signal", "L0", cumulative=False,
         notes="the patch-High-and-above policy"),
    Rung("L2", "EPSS only", "exploit probability", "Single signal", "L0",
         cumulative=False, notes="the strongest single-signal baseline"),
    Rung("L3", "CVSS + EPSS", "fusion of the two scores", "Fused base", "L0",
         notes="K-CAVP base classification with no threat or context refinement"),
    Rung("L4", "+ CISA KEV", "confirmed exploitation", "Threat intelligence", "L3",
         inert_on_cve_level=INERT_PROTOCOL),
    Rung("L5", "+ public exploit code", "exploit availability", "Threat intelligence",
         "L4"),
    Rung("L6", "+ Kubernetes context", "deployed / exposed / privileged",
         "Deployment context", "L5", inert_on_cve_level=INERT_NO_SIGNAL),
    Rung("L7", "+ Falco runtime", "attributed runtime evidence", "Runtime", "L6",
         inert_on_cve_level=INERT_NO_SIGNAL),
)

# The five-stage view for the waterfall figure, collapsing the two threat-intelligence
# rungs and dropping the single-signal alternatives. Keys are the rung that ends each
# stage.
COLLAPSED_STAGES = ("L0", "L3", "L5", "L6", "L7")


def build_ladder(thresholds: Thresholds | None = None) -> dict[str, Baseline]:
    """
    One method instance per rung, keyed by rung id.

    Every rung from L3 up is the same `KCAVP` class with a different set of enabled
    layers, so no rung can drift from the implementation actually under test.
    """
    def kcavp(**flags) -> KCAVP:
        base = dict(enable_kev=False, enable_exploit=False, enable_context=False,
                    enable_runtime=False)
        return KCAVP(thresholds=thresholds, variant="ladder", **(base | flags))

    return {
        "L0": ScanOnly(),
        "L1": CvssOnly(),
        "L2": EpssOnly(),
        "L3": kcavp(),
        "L4": kcavp(enable_kev=True),
        "L5": kcavp(enable_kev=True, enable_exploit=True),
        "L6": kcavp(enable_kev=True, enable_exploit=True, enable_context=True),
        "L7": kcavp(enable_kev=True, enable_exploit=True, enable_context=True,
                    enable_runtime=True),
    }


def ladder_rows(summary: dict, rungs: tuple[Rung, ...] = RUNGS) -> list[dict]:
    """
    Turn per-rung metrics into table rows carrying the marginal effect of each layer.

    `delta_actionable` is negative when a rung *removes* findings from the queue, which
    is the direction the ladder is about. `delta_recall` is the recall paid for that
    removal; a rung that removes findings at no recall cost is free noise reduction, and
    one that removes recall without removing enough findings is not worth its
    complexity. Both readings need the pair, which is why they are computed together.
    """
    rows = []
    for rung in rungs:
        s = summary.get(rung.key)
        if s is None:
            continue
        row = {
            "rung": rung.key,
            "label": rung.label,
            "adds": rung.adds,
            "stage": rung.stage,
            "cumulative": rung.cumulative,
            "actionable": s["actionable"],
            "workload_reduction": s["workload_reduction"],
            "recall": s["recall"],
            "efficiency": s.get("efficiency"),
            "compare_to": rung.compare_to or "",
            "delta_actionable": None,
            "delta_reduction": None,
            "delta_recall": None,
            "inert": rung.inert_on_cve_level,
            "notes": rung.notes,
        }
        prev = summary.get(rung.compare_to) if rung.compare_to else None
        if prev is not None:
            row["delta_actionable"] = s["actionable"] - prev["actionable"]
            row["delta_reduction"] = _sub(s["workload_reduction"],
                                          prev["workload_reduction"])
            row["delta_recall"] = _sub(s["recall"], prev["recall"])
        rows.append(row)
    return rows


def collapsed_rows(rows: list[dict], stages=COLLAPSED_STAGES) -> list[dict]:
    """The five-stage waterfall, for the figure rather than the full table."""
    by_key = {r["rung"]: r for r in rows}
    out = []
    previous = None
    for key in stages:
        row = by_key.get(key)
        if row is None:
            continue
        entry = dict(row)
        if previous is not None:
            entry["delta_actionable"] = row["actionable"] - previous["actionable"]
            entry["delta_reduction"] = _sub(row["workload_reduction"],
                                            previous["workload_reduction"])
            entry["delta_recall"] = _sub(row["recall"], previous["recall"])
            entry["compare_to"] = previous["rung"]
        else:
            entry["delta_actionable"] = None
            entry["delta_reduction"] = None
            entry["delta_recall"] = None
            entry["compare_to"] = ""
        out.append(entry)
        previous = row
    return out


def inert_rungs(rows: list[dict]) -> list[dict]:
    """
    Rungs that were predicted inert and rungs that turned out flat unexpectedly.

    Separating the two matters: a rung documented as structurally unmeasurable on this
    dataset is expected to be flat, while an undocumented flat rung is a finding (or a
    bug) and should not be quietly absorbed into the table.
    """
    findings = []
    for row in rows:
        moved = bool(row["delta_actionable"])
        if row["inert"] and moved:
            findings.append({**row, "status": "expected inert but moved"})
        elif not row["inert"] and row["compare_to"] and not moved:
            findings.append({**row, "status": "unexpectedly flat"})
        elif row["inert"]:
            findings.append({**row, "status": "inert as documented"})
    return findings


def _sub(a, b):
    return None if a is None or b is None else a - b
