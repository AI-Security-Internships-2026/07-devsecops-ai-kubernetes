"""
SSVC decision logic (pure, no external dependencies).

Kept free of LangGraph / network so it can be tested in isolation.

Base classification (EPSS + CVSS + KEV) is the Phase-0 behaviour. Optional
refinements plug in here without changing callers:
  - apply_context()  — Kubernetes deployment context
  - apply_exploit()  — public-exploit-exists signal for SSVC "Automatable"
  - apply_runtime()  — Falco runtime-reachability signal (image is live/active)
"""

# Priority <-> SSVC decision label
PRIORITY_TO_DECISION = {
    "CRITICAL": "Act",
    "HIGH": "Attend",
    "MEDIUM": "Track*",
    "LOW": "Track",
}
# Ordered low -> high, for escalate/de-escalate steps
_LADDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def decision_for(priority: str) -> str:
    """Map a priority level to its SSVC decision label."""
    return PRIORITY_TO_DECISION.get(priority, "Track")


def _step(priority: str, delta: int) -> str:
    """Move a priority up (+) or down (-) the ladder, clamped."""
    idx = _LADDER.index(priority) if priority in _LADDER else 0
    idx = max(0, min(len(_LADDER) - 1, idx + delta))
    return _LADDER[idx]


def classify_priority(cve: dict, in_kev: bool) -> tuple[str, str]:
    """
    Apply the base CISA SSVC decision tree. Returns (priority, ssvc_decision).

    Base thresholds:
        CRITICAL / Act    — EPSS >= 0.1 OR in CISA KEV
        HIGH / Attend     — EPSS >= 0.01 AND (CVSS >= 7.0 OR CRITICAL/HIGH severity)
        MEDIUM / Track*   — EPSS >= 0.01
        LOW / Track       — everything else
    """
    epss = cve.get("epss_score", 0.0)
    cvss = cve.get("cvss_score", 0.0)
    severity = cve.get("severity", "UNKNOWN").upper()

    if epss >= 0.1 or in_kev:
        priority = "CRITICAL"
    elif epss >= 0.01 and (cvss >= 7.0 or severity in ("CRITICAL", "HIGH")):
        priority = "HIGH"
    elif epss >= 0.01:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return priority, decision_for(priority)


def apply_exploit(priority: str, cve: dict, exploit_exists: bool) -> tuple[str, str | None]:
    """
    SSVC "Automatable" refinement (P4). A public exploit makes a borderline
    finding more urgent. KEV items are already CRITICAL so no change there.

    Returns (new_priority, note_or_None).
    """
    if not exploit_exists:
        return priority, None
    if priority in ("HIGH", "MEDIUM"):
        new_p = _step(priority, +1)
        return new_p, f"escalated {priority}->{new_p}: public exploit code exists (Automatable)"
    return priority, "public exploit code exists"


def analyze(cve: dict, in_kev: bool, context: dict | None = None,
            exploit_exists: bool = False, runtime: dict | None = None) -> dict:
    """
    Full deterministic analysis for one finding: base SSVC, then exploit, context
    and runtime refinements. Single source of truth shared by the agent and tests.

    Returns {"priority", "decision", "notes"}.
    """
    priority, _ = classify_priority(cve, in_kev)
    notes: list[str] = []

    priority, note = apply_exploit(priority, cve, exploit_exists)
    if note:
        notes.append(note)

    priority, note = apply_context(priority, cve, context)
    if note:
        notes.append(note)

    priority, note = apply_runtime(priority, cve, runtime)
    if note:
        notes.append(note)

    return {"priority": priority, "decision": decision_for(priority), "notes": notes}


def apply_context(priority: str, cve: dict, context: dict | None) -> tuple[str, str | None]:
    """
    Kubernetes deployment-context refinement (P3).

    Adjusts a finding by AT MOST ONE level and never touches the MEDIUM/LOW tiers,
    so context re-ranks urgency within the already-actionable set without inflating
    it. Rules (must match the code below):
      - not deployed anywhere                         -> de-escalate to LOW
      - HIGH + EPSS >= 0.05 + exposed/privileged      -> escalate to CRITICAL
      - CRITICAL, internal-only, not KEV, EPSS < 0.2  -> de-escalate to HIGH
        (kills EPSS-inflated false criticals like BEAST when unreachable)

    `context` shape: {available: bool, deployed: bool, exposed: bool,
                      exposure_type: str, namespace: str, privileged: bool,
                      sa_privileged: bool}
    Returns (new_priority, note_or_None). No cluster / not available -> unchanged.
    """
    if not context or not context.get("available"):
        return priority, None

    epss = cve.get("epss_score", 0.0)
    in_kev = cve.get("in_kev", False)
    exposed = bool(context.get("exposed"))
    privileged = bool(context.get("privileged") or context.get("sa_privileged"))

    # Not deployed in this cluster -> not actionable here.
    if context.get("deployed") is False:
        if priority != "LOW":
            return "LOW", f"de-escalated {priority}->LOW: image not deployed in cluster"
        return priority, None

    # Context adjusts a finding by AT MOST ONE level (no stacking), and only in
    # ways that keep the actionable set meaningful. Escalation NEVER touches the
    # MEDIUM/LOW tiers, so deployment context can re-rank urgency within the
    # already-actionable set but never invents new actionable work.

    # ESCALATE (+1): an already-actionable, genuinely-exploitable HIGH finding
    # (EPSS >= 0.05) becomes urgent on an internet-facing or privileged pod.
    if priority == "HIGH" and epss >= 0.05 and (exposed or privileged):
        reason = "internet-facing" if exposed else "privileged pod"
        return "CRITICAL", f"escalated HIGH->CRITICAL: {reason} + EPSS {epss:.3f}"

    # DE-ESCALATE (-1, noise reduction): a borderline CRITICAL driven by moderate
    # EPSS (0.1-0.2), not confirmed-exploited, on an internal-only non-privileged
    # pod is not actually urgent here.
    if (
        priority == "CRITICAL"
        and not exposed
        and not privileged
        and not in_kev
        and epss < 0.2
    ):
        return "HIGH", f"de-escalated CRITICAL->HIGH: internal-only, not in CISA KEV (EPSS {epss:.3f})"

    return priority, None


# Falco alert priorities, most-severe tier that ESCALATES. Lower tiers (Warning,
# Notice, ...) only annotate the rationale.
_FALCO_CRITICAL_TIER = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR"}


def apply_runtime(priority: str, cve: dict, runtime: dict | None) -> tuple[str, str | None]:
    """
    Kubernetes runtime-reachability refinement (Falco), two-tier.

    Falco maps alerts to a pod/container/image, not to a CVE, so this is an
    IMAGE-LEVEL signal applied to the findings in that image — "is the vulnerable
    component actually live and active?" — not per-CVE exploitation proof.

    Tiers:
      - a CRITICAL-tier Falco alert (Emergency/Alert/Critical/Error) on the image
        escalates an already-actionable HIGH -> CRITICAL (at most one level;
        never touches MEDIUM/LOW),
      - anything else (lower-severity alerts, or a critical-tier alert on a
        non-HIGH finding) is only recorded in the rationale — no level change.

    `runtime` shape: {available: bool, count: int, max_priority: str,
                      rules: list[str]}. No signal / not available -> unchanged.
    Returns (new_priority, note_or_None).
    """
    if not runtime or not runtime.get("available"):
        return priority, None
    count = int(runtime.get("count", 0) or 0)
    if count == 0:
        return priority, None

    max_pri = (runtime.get("max_priority") or "").upper()
    rules = runtime.get("rules") or ["runtime activity"]
    rule = rules[0] if rules else "runtime activity"
    critical_tier = max_pri in _FALCO_CRITICAL_TIER

    # ESCALATE (+1): critical-tier runtime alert on an already-actionable HIGH.
    if critical_tier and priority == "HIGH":
        return "CRITICAL", (
            f"escalated HIGH->CRITICAL: Falco {max_pri.title()} runtime alert on this "
            f"image (\"{rule}\") — vulnerable component is live and active"
        )

    # ANNOTATE only (no level change) for everything else.
    tier = "critical-tier" if critical_tier else "low-severity"
    return priority, (
        f"runtime activity observed on this image "
        f"(Falco {max_pri.title() or 'alert'}, {count} alert(s), {tier}); decision unchanged"
    )
