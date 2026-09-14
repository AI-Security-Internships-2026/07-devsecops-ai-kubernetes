"""Baseline E — deterministic KEV/EPSS/CVSS chaining (issue #20)."""

from src.baselines.base import (ACTIONABLE, NOT_ACTIONABLE, Baseline, Decision,
                                as_bool, as_float)
from src.triage.thresholds import DEFAULTS


class DeterministicChaining(Baseline):
    """
    A credible non-Kubernetes fusion comparator: all three global signals combined by
    explicit rules, with no deployment or runtime context.

    This is the hardest baseline for our contribution claim to beat, and that is the
    point. It isolates what Kubernetes context actually adds: if K-CAVP cannot outperform
    a well-built signal fusion that lacks cluster awareness, the cluster awareness is not
    earning its place.

    Rules, in order:
      1. in KEV                               -> actionable (confirmed exploitation)
      2. EPSS >= act threshold                -> actionable
      3. public exploit AND CVSS >= high      -> actionable (severe + weaponised)
      4. EPSS >= attend AND CVSS >= high      -> actionable (measurable risk + severe)
      5. otherwise                            -> not actionable

    Not a reimplementation of any specific published system; documented explicitly so it
    can be reproduced and criticised.
    """

    name = "chaining"
    description = "Deterministic KEV/EPSS/CVSS fusion, no deployment context"
    uses_signals = ("kev", "epss", "cvss_severity", "public_exploit")

    def __init__(self, epss_act: float | None = None, epss_attend: float | None = None,
                 cvss_high: float | None = None):
        self.epss_act = DEFAULTS.epss_act if epss_act is None else epss_act
        self.epss_attend = DEFAULTS.epss_attend if epss_attend is None else epss_attend
        self.cvss_high = DEFAULTS.cvss_high if cvss_high is None else cvss_high

    def decide(self, record: dict) -> Decision:
        epss = as_float(record.get("epss_score"))
        cvss = as_float(record.get("cvss_score"))
        severity = (record.get("cvss_severity") or "").upper()
        in_kev = as_bool(record.get("kev_at_snapshot"))
        exploit = as_bool(record.get("public_exploit_at_snapshot"))
        severe = cvss >= self.cvss_high or severity in ("HIGH", "CRITICAL")

        if in_kev:
            rule, hit, base = "KEV: confirmed exploitation", True, 3.0
        elif epss >= self.epss_act:
            rule, hit, base = f"EPSS {epss:.5f} >= {self.epss_act}", True, 2.0
        elif exploit and severe:
            rule, hit, base = f"public exploit + CVSS {cvss}", True, 1.5
        elif epss >= self.epss_attend and severe:
            rule, hit, base = f"EPSS {epss:.5f} >= {self.epss_attend} + CVSS {cvss}", True, 1.0
        else:
            rule, hit, base = "no rule matched", False, 0.0

        # Band dominates; EPSS orders within a band so ranking stays informative.
        return Decision(
            cve_id=record["cve_id"], method=self.name,
            score=base + min(epss, 0.999),
            decision=ACTIONABLE if hit else NOT_ACTIONABLE,
            explanation=rule,
            signals={"kev": in_kev, "epss": epss, "cvss": cvss, "public_exploit": exploit},
        )
