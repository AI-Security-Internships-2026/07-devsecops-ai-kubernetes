"""
SSVC decision logic (pure, no external dependencies).

Kept free of LangGraph / network so it can be unit-tested in isolation.

Base classification (EPSS + CVSS + KEV) is the Phase-0 behaviour. Two optional
refinements plug in here without changing callers:
  - apply_context()  — Kubernetes deployment context (P3)
  - apply_exploit()  — public-exploit-exists signal for SSVC "Automatable" (P4)
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
            exploit_exists: bool = False) -> dict:
    """
    Full deterministic analysis for one finding: base SSVC, then exploit and
    context refinements. Single source of truth shared by the agent and tests.

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

    return {"priority": priority, "decision": decision_for(priority), "notes": notes}


def apply_context(priority: str, cve: dict, context: dict | None) -> tuple[str, str | None]:
    """
    Kubernetes deployment-context refinement (P3).

    Rules:
      - not deployed anywhere          -> de-escalate to LOW (report as not-deployed)
      - internet-facing + EPSS >= 0.01 -> escalate one level
      - privileged / cluster-admin SA  -> escalate one level
      - internal-only borderline CRITICAL (not KEV, EPSS < 0.3) -> de-escalate to HIGH
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

    if context.get("deployed") is False:
        if priority != "LOW":
            return "LOW", f"de-escalated {priority}->LOW: image not deployed in cluster"
        return priority, None

    note = None
    new_p = priority

    if context.get("exposed") and epss >= 0.01:
        stepped = _step(new_p, +1)
        if stepped != new_p:
            note = f"escalated {new_p}->{stepped}: internet-facing ({context.get('exposure_type', 'exposed')})"
            new_p = stepped

    if context.get("privileged") or context.get("sa_privileged"):
        stepped = _step(new_p, +1)
        if stepped != new_p:
            reason = "privileged pod" if context.get("privileged") else "cluster-admin service account"
            note = f"escalated {new_p}->{stepped}: {reason}"
            new_p = stepped

    if (
        new_p == "CRITICAL"
        and not in_kev
        and epss < 0.3
        and context.get("exposed") is False
    ):
        note = "de-escalated CRITICAL->HIGH: internal-only, not KEV, moderate EPSS"
        new_p = "HIGH"

    return new_p, note
