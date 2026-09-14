"""
Baseline D — official SSVC Deployer decision table (issue #20).

This is the comparator that matters most for positioning, because K-CAVP borrows SSVC's
vocabulary. If we are going to say our method differs from SSVC, the real SSVC has to be
in the comparison, evaluated on the same records.

The decision table is the **official one**, vendored verbatim from CERTCC/SSVC
(`deployer_patch_application_priority_1_0_0.csv`, 72 rows) rather than reimplemented from
the prose. Reimplementing a 72-row table from memory is exactly the kind of error that
produces a wrong baseline and is almost impossible to spot afterwards.

What can and cannot be derived
------------------------------
The Deployer tree needs four decision points. Our data supplies two of them honestly and
cannot supply the other two:

| Decision point | Source | Status |
|---|---|---|
| **Exploitation** | KEV -> `active`; public exploit -> `public poc`; else `none` | ✅ derived |
| **System Exposure** | Kubernetes context: exposed -> `open`, internal -> `controlled`, not deployed -> `small` | ✅ derived *when cluster context exists* |
| **Automatable** | public exploit availability used as a proxy | ⚠️ **approximated** |
| **Human Impact** | Safety Impact x Mission Impact — asset criticality, not a CVE property | ❌ **not derivable, defaulted** |

`Automatable` in SSVC asks whether an attacker can reliably automate the first four
kill-chain steps. Public exploit availability correlates with that but is not the same
claim, so it is recorded as an approximation rather than presented as the real input.

`Human Impact` depends on what the affected system *does* for the organisation. No CVE
feed contains that. It is defaulted, the default is a constructor parameter, and the
default materially shifts the whole baseline — so results must state which value was used,
and ideally report more than one.

On the historical dataset there is no cluster, so `System Exposure` is defaulted too. This
is a real limitation of comparing against SSVC on CVE-level data, and it is reported per
run rather than buried: `provenance()` returns which inputs were derived and which were
assumed.
"""

import csv
from functools import lru_cache
from pathlib import Path

from src.baselines.base import (ACTIONABLE, NOT_ACTIONABLE, Baseline, Decision,
                                as_bool, as_float)

TABLE_PATH = Path(__file__).parent / "data" / "deployer_patch_application_priority_1_0_0.csv"

# Outcome -> (ordinal, actionable). SSVC's Deployer outcomes are a priority ladder;
# "defer" and "scheduled" mean the analyst is not acting now, which is the same question
# the other baselines answer with "actionable".
OUTCOMES = {
    "defer":        (0, False),
    "scheduled":    (1, False),
    "out-of-cycle": (2, True),
    "immediate":    (3, True),
}

EXPLOITATION = ("none", "public poc", "active")
EXPOSURE = ("small", "controlled", "open")
AUTOMATABLE = ("no", "yes")
HUMAN_IMPACT = ("low", "medium", "high", "very high")


@lru_cache(maxsize=1)
def load_table() -> dict[tuple[str, str, str, str], str]:
    """The official Deployer table as {(exploitation, exposure, automatable, impact): outcome}."""
    table = {}
    with open(TABLE_PATH, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row["Exploitation v1.1.0"].strip().lower(),
                   row["System Exposure v1.0.1"].strip().lower(),
                   row["Automatable v2.0.0"].strip().lower(),
                   row["Human Impact v2.0.2"].strip().lower())
            table[key] = row["Defer, Scheduled, Out-of-Cycle, Immediate v1.0.0"].strip().lower()
    expected = len(EXPLOITATION) * len(EXPOSURE) * len(AUTOMATABLE) * len(HUMAN_IMPACT)
    if len(table) != expected:
        raise ValueError(f"SSVC table has {len(table)} rows, expected {expected} — "
                         f"the vendored file may be truncated or a different version")
    return table


def exploitation_state(record: dict) -> str:
    """
    SSVC `Exploitation`, derived faithfully.

    KEV membership is confirmed active exploitation, which is precisely SSVC's `active`.
    A published exploit is `public poc`. This is the one decision point our data maps to
    without approximation.
    """
    if as_bool(record.get("kev_at_snapshot")):
        return "active"
    if as_bool(record.get("public_exploit_at_snapshot")):
        return "public poc"
    return "none"


def exposure_state(record: dict, default: str = "controlled") -> tuple[str, bool]:
    """
    SSVC `System Exposure` from Kubernetes context. Returns (state, derived).

    Absent cluster context the value is assumed, and the caller is told so — silently
    defaulting would make the baseline look better or worse than it is with no trace.
    """
    ctx = record.get("k8s_context") or {}
    if not ctx or not ctx.get("available"):
        return default, False
    if ctx.get("deployed") is False:
        return "small", True
    if ctx.get("exposed"):
        return "open", True
    return "controlled", True


class OfficialSSVC(Baseline):
    """
    The official SSVC Deployer tree, applied to our records.

    Ranked by outcome ordinal with EPSS as a tie-break: the tree is coarse (four
    outcomes), so without a tie-break every finding sharing an outcome would be ordered
    arbitrarily and Precision@K would measure sort stability rather than the method.
    """

    name = "official_ssvc"
    description = ("Official SSVC Deployer decision table (CERTCC v1.0.0, 72 rows); "
                   "Human Impact assumed, Automatable approximated by public exploit")
    uses_signals = ("kev", "public_exploit", "k8s_deployed", "k8s_exposure")

    def __init__(self, human_impact: str = "medium", default_exposure: str = "controlled"):
        if human_impact not in HUMAN_IMPACT:
            raise ValueError(f"human_impact must be one of {HUMAN_IMPACT}")
        if default_exposure not in EXPOSURE:
            raise ValueError(f"default_exposure must be one of {EXPOSURE}")
        self.human_impact = human_impact
        self.default_exposure = default_exposure
        self._exposure_derived = 0
        self._total = 0

    def decide(self, record: dict) -> Decision:
        table = load_table()
        exploitation = exploitation_state(record)
        exposure, derived = exposure_state(record, self.default_exposure)
        # Automatable: approximated by public exploit availability. Recorded as an
        # approximation in provenance() rather than presented as the real decision point.
        automatable = "yes" if as_bool(record.get("public_exploit_at_snapshot")) else "no"

        self._total += 1
        self._exposure_derived += int(derived)

        outcome = table[(exploitation, exposure, automatable, self.human_impact)]
        ordinal, actionable = OUTCOMES[outcome]
        epss = as_float(record.get("epss_score"))

        return Decision(
            cve_id=record["cve_id"],
            method=self.name,
            # Ordinal dominates; EPSS (< 1) breaks ties within an outcome band.
            score=ordinal + min(epss, 0.999),
            decision=ACTIONABLE if actionable else NOT_ACTIONABLE,
            priority=outcome,
            explanation=(f"SSVC Deployer: exploitation={exploitation}, "
                         f"exposure={exposure}{'' if derived else ' (assumed)'}, "
                         f"automatable={automatable} (approximated), "
                         f"human_impact={self.human_impact} (assumed) -> {outcome}"),
            signals={"exploitation": exploitation, "exposure": exposure,
                     "automatable": automatable, "human_impact": self.human_impact},
        )

    def provenance(self) -> dict:
        """
        Which decision points were derived from data and which were assumed.

        Reported alongside the results so a reader can weigh the SSVC comparison
        appropriately — with two of four inputs assumed, it is a reference point, not a
        like-for-like contest.
        """
        return {
            "table": TABLE_PATH.name,
            "table_rows": len(load_table()),
            "exploitation": "derived (KEV -> active, public exploit -> public poc)",
            "system_exposure": (
                f"derived for {self._exposure_derived}/{self._total} records; "
                f"assumed '{self.default_exposure}' otherwise"),
            "automatable": "APPROXIMATED by public exploit availability",
            "human_impact": f"ASSUMED '{self.human_impact}' — not derivable from CVE data",
        }
