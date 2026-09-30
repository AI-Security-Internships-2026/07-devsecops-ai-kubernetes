"""
K-CAVP decision logic (pure, no external dependencies).

Kubernetes Context-Aware Vulnerability Prioritization. The method borrows SSVC's
decision vocabulary (Act / Attend / Track* / Track) but does NOT implement the
official SSVC Deployer decision table, so it is deliberately not called SSVC.

Kept free of LangGraph / network so it can be tested in isolation.

Base classification (EPSS + CVSS + KEV) is the Phase-0 behaviour. Optional
refinements plug in here without changing callers:
  - apply_context()  — Kubernetes deployment context
  - apply_exploit()  — public-exploit-exists signal ("Automatable")
  - apply_runtime()  — Falco runtime evidence, attributed to packages

Every numeric cut-off lives in src/triage/thresholds.py, with its provenance
recorded, so the threshold sensitivity sweep can vary them without editing this
module and the paper can cite one location.
"""

from src.triage.thresholds import DEFAULTS, FALCO_CRITICAL_TIER, Thresholds

# ---------------------------------------------------------------------------
# Operating modes (issue #19 item 6).
#
# The same deployment-context rule is correct in one mode and dangerous in the other,
# so the mode has to be explicit rather than implied by whatever context happened to be
# passed.
#
# CLUSTER: we are triaging against a live cluster we can query. "This image is not
#   running anywhere" is a *positive observation* and legitimately de-escalates.
#
# PRE_DEPLOYMENT: we are gating an image in CI, before it is deployed. The image is
#   not running BY DEFINITION, and that fact carries no information about risk. Applying
#   the cluster rule here de-escalates every finding in exactly the place the pipeline is
#   supposed to block — the defect recorded in PR-Week10 and only partially patched by
#   the KEV exemption, which left every non-KEV finding still wrongly deferred.
#
# Runtime evidence is likewise unavailable pre-deployment: there is no running container
# to observe, so an alert supplied in this mode describes some other workload and must
# not escalate.
# ---------------------------------------------------------------------------
MODE_CLUSTER = "cluster"
MODE_PRE_DEPLOYMENT = "pre_deployment"
MODES = (MODE_CLUSTER, MODE_PRE_DEPLOYMENT)


def resolve_mode(context: dict | None, runtime: dict | None = None,
                 mode: str | None = None) -> str:
    """
    The mode in force for one analysis.

    An explicit mode always wins. Otherwise it is inferred from whether we have any
    observation of a live workload: reachable cluster context, or runtime evidence.

    Runtime evidence counts on its own. Falco alerts can only be produced by a container
    that is actually running, so their presence is direct proof that this is not a
    pre-deployment gate, even when the Kubernetes API was unreachable. Inferring
    pre-deployment from a missing cluster connection alone would silence genuine runtime
    escalations whenever context lookup failed — which is a failure mode the test suite
    caught when this function first ignored `runtime`.

    Inference is a convenience for callers written before the split; the pipeline passes
    the mode explicitly and the resolved value is recorded in every result, so a stored
    decision can always be read back with the rule set that produced it.
    """
    if mode is not None:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")
        return mode
    observed_live = bool((context or {}).get("available")
                         or (runtime or {}).get("available"))
    return MODE_CLUSTER if observed_live else MODE_PRE_DEPLOYMENT


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


def classify_priority(cve: dict, in_kev: bool,
                      thresholds: Thresholds | None = None) -> tuple[str, str]:
    """
    Apply the base CISA SSVC decision tree. Returns (priority, ssvc_decision).

    Base thresholds (values and provenance in src/triage/thresholds.py):
        CRITICAL / Act    — EPSS >= epss_act OR in CISA KEV
        HIGH / Attend     — EPSS >= epss_attend AND (CVSS >= cvss_high
                            OR CRITICAL/HIGH severity)
        MEDIUM / Track*   — EPSS >= epss_attend
        LOW / Track       — everything else
    """
    t = thresholds or DEFAULTS
    epss = cve.get("epss_score", 0.0)
    cvss = cve.get("cvss_score", 0.0)
    severity = cve.get("severity", "UNKNOWN").upper()

    if epss >= t.epss_act or in_kev:
        priority = "CRITICAL"
    elif epss >= t.epss_attend and (cvss >= t.cvss_high
                                    or severity in ("CRITICAL", "HIGH")):
        priority = "HIGH"
    elif epss >= t.epss_attend:
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
            exploit_exists: bool = False, runtime: dict | None = None,
            thresholds: Thresholds | None = None,
            mode: str | None = None) -> dict:
    """
    Full deterministic analysis for one finding: base SSVC, then exploit, context
    and runtime refinements. Single source of truth shared by the agent and tests.

    `mode` selects the rule set (see MODES). Left as None it is inferred from whether
    cluster context was available, which preserves the behaviour of callers written
    before the split; the pipeline passes it explicitly.

    Returns {"priority", "decision", "notes", "mode"} — the resolved mode is returned so
    a stored decision records which rule set produced it.

    Each refinement is individually capped at one level, but that is not the same
    as the FINDING being capped: exploit could lift MEDIUM->HIGH and runtime then
    lift HIGH->CRITICAL, moving a finding two levels off its evidence base. That
    is the same failure mode as the original escalation-stacking bug, reached by a
    different pair of signals, so the total is clamped here as well.

    Only UPWARD movement is clamped. De-escalation is noise reduction and is
    allowed to travel further — "image not deployed in this cluster" legitimately
    drops a finding straight to LOW.
    """
    t = thresholds or DEFAULTS
    resolved_mode = resolve_mode(context, runtime, mode)
    base, _ = classify_priority(cve, in_kev, t)
    priority = base
    notes: list[str] = []

    priority, note = apply_exploit(priority, cve, exploit_exists)
    if note:
        notes.append(note)

    priority, note = apply_context(priority, cve, context, t, resolved_mode)
    if note:
        notes.append(note)

    priority, note = apply_runtime(priority, cve, runtime, resolved_mode)
    if note:
        notes.append(note)

    priority, note = _cap_total_escalation(base, priority, t)
    if note:
        notes.append(note)

    return {"priority": priority, "decision": decision_for(priority), "notes": notes,
            "mode": resolved_mode}


def _cap_total_escalation(base: str, priority: str,
                          thresholds: Thresholds | None = None) -> tuple[str, str | None]:
    """
    Clamp a finding to at most ONE level above its base classification.

    The refinements answer "is this more urgent than the raw scores suggest?" —
    they are corroborating context, not independent evidence, so several of them
    agreeing must not compound into a two-level jump. Keeping the ceiling at +1
    is what makes the escalation bound a property of the tool rather than of the
    particular signals that happened to fire.
    """
    t = thresholds or DEFAULTS
    if t.max_escalation_levels < 0:          # unbounded variant (experiment 6B)
        return priority, None
    if base not in _LADDER or priority not in _LADDER:
        return priority, None
    ceiling = min(_LADDER.index(base) + t.max_escalation_levels, len(_LADDER) - 1)
    if _LADDER.index(priority) <= ceiling:
        return priority, None
    capped = _LADDER[ceiling]
    levels = t.max_escalation_levels
    allowance = "may not be raised above" if levels == 0 else         f"may raise a finding at most {levels} level{'s' if levels != 1 else ''} above"
    return capped, (f"capped {priority}->{capped}: refinements {allowance} "
                    f"its {base} base classification")


def apply_context(priority: str, cve: dict, context: dict | None,
                  thresholds: Thresholds | None = None,
                  mode: str = MODE_CLUSTER) -> tuple[str, str | None]:
    """
    Kubernetes deployment-context refinement (P3).

    Adjusts a finding by AT MOST ONE level and never touches the MEDIUM/LOW tiers,
    so context re-ranks urgency within the already-actionable set without inflating
    it. Rules (must match the code below):
      - not deployed anywhere (and not KEV)                        -> de-escalate to LOW
      - HIGH + EPSS >= epss_context_escalate + exposed/privileged  -> escalate to CRITICAL
      - CRITICAL, internal-only, not KEV,
        EPSS < epss_context_deescalate                             -> de-escalate to HIGH
        (kills EPSS-inflated false criticals like BEAST when unreachable)

    `context` shape: {available: bool, deployed: bool, exposed: bool,
                      exposure_type: str, namespace: str, privileged: bool,
                      sa_privileged: bool}
    Returns (new_priority, note_or_None). No cluster / not available -> unchanged.
    """
    if not context or not context.get("available"):
        return priority, None

    t = thresholds or DEFAULTS
    epss = cve.get("epss_score", 0.0)
    in_kev = cve.get("in_kev", False)
    exposed = bool(context.get("exposed"))
    privileged = bool(context.get("privileged") or context.get("sa_privileged"))

    # Not deployed -> not actionable *in this cluster*. The rule is only sound when we
    # actually queried a cluster and observed the image absent from it.
    #
    # In PRE_DEPLOYMENT mode the image is not running by definition, so "not deployed"
    # is not an observation and must not de-escalate anything. The earlier KEV exemption
    # was a partial patch for the same defect: it rescued known-exploited findings but
    # left every other finding in a CI gate silently filed as Track. Mode is the
    # complete fix; the KEV exemption remains below because it is still needed in
    # CLUSTER mode, where an image genuinely absent today may be deployed tomorrow.
    if context.get("deployed") is False:
        if mode == MODE_PRE_DEPLOYMENT:
            return priority, ("pre-deployment scan: image is not running by definition, "
                              "so deployment state carries no evidence — not "
                              "de-escalated")
        if in_kev:
            return priority, ("image not deployed in cluster, but CVE is in CISA KEV "
                              "(actively exploited) — not de-escalated")
        if priority != "LOW":
            return "LOW", f"de-escalated {priority}->LOW: image not deployed in cluster"
        return priority, None

    # Context adjusts a finding by AT MOST ONE level (no stacking), and only in
    # ways that keep the actionable set meaningful. Escalation NEVER touches the
    # MEDIUM/LOW tiers, so deployment context can re-rank urgency within the
    # already-actionable set but never invents new actionable work.

    # ESCALATE (+1): an already-actionable, genuinely-exploitable HIGH finding
    # (EPSS >= 0.05) becomes urgent on an internet-facing or privileged pod.
    if (priority == "HIGH" and epss >= t.epss_context_escalate
            and (exposed or privileged)):
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
        and epss < t.epss_context_deescalate
    ):
        return "HIGH", f"de-escalated CRITICAL->HIGH: internal-only, not in CISA KEV (EPSS {epss:.3f})"

    return priority, None


# Falco alert priorities severe enough to be eligible to escalate. Defined once in
# thresholds.py so the paper and the sweep reference a single source.
_FALCO_CRITICAL_TIER = FALCO_CRITICAL_TIER


def _packages_of(cve: dict) -> list[str]:
    """Package names a finding affects, however the scanner spelled the field."""
    pkgs = cve.get("affected_packages") or cve.get("packages") or []
    if isinstance(pkgs, str):
        pkgs = [pkgs]
    out = []
    for p in pkgs:
        # Trivy findings carry either bare names or {name, version} records.
        name = p.get("name") if isinstance(p, dict) else p
        if name:
            out.append(str(name))
    return out


def _attributed_alert(cve: dict, alerts: list[dict]) -> dict | None:
    """
    The first critical-tier alert that is evidence about THIS finding.

    An alert is evidence about a finding only when the package it implicates is a
    package the finding affects. That intersection is the whole point of issue #17:
    without it, a shell spawned in a container escalates a TLS-library CVE that the
    shell never touched.
    """
    pkgs = {p.lower() for p in _packages_of(cve)}
    if not pkgs:
        return None
    for alert in alerts:
        if (alert.get("priority") or "").upper() not in _FALCO_CRITICAL_TIER:
            continue
        hit = {str(p).lower() for p in (alert.get("packages") or [])}
        if hit & pkgs:
            return {**alert, "matched": sorted(hit & pkgs)}
    return None


def apply_runtime(priority: str, cve: dict, runtime: dict | None,
                  mode: str = MODE_CLUSTER) -> tuple[str, str | None]:
    """
    Kubernetes runtime-reachability refinement (Falco), two-tier.

    Escalation requires ATTRIBUTED evidence: a critical-tier alert whose implicated
    package is one the finding actually affects. Falco reports behaviour and Trivy
    reports packages, so without that link the signal is only about the image, and
    one unrelated alert would escalate every borderline finding on it (issue #17).

    Tiers:
      - a CRITICAL-tier alert (Emergency/Alert/Critical/Error) attributed to a package
        this finding affects escalates an already-actionable HIGH -> CRITICAL (one
        level at most; never touches MEDIUM/LOW),
      - everything else is recorded in the rationale only — lower-severity alerts, a
        critical-tier alert on a non-HIGH finding, and critically also an alert that
        could NOT be attributed to this finding's packages. Unattributable evidence
        annotates; it never escalates.

    `runtime` shape: {available: bool, count: int, max_priority: str,
                      rules: list[str], alerts: list[dict]} where each alert carries
    at least {priority, rule, packages, process, exepath}. Without `alerts` there is
    no evidence to attribute, so the signal can only annotate.
    Returns (new_priority, note_or_None).
    """
    if not runtime or not runtime.get("available"):
        return priority, None
    count = int(runtime.get("count", 0) or 0)
    if count == 0:
        return priority, None

    # A pre-deployment gate has no running container of this image to observe. Any
    # alerts handed to us describe some other workload, so they are recorded and
    # explicitly not acted on rather than silently dropped.
    if mode == MODE_PRE_DEPLOYMENT:
        return priority, (f"pre-deployment scan: {count} runtime alert(s) supplied but "
                          f"this image is not running — recorded, no change")

    max_pri = (runtime.get("max_priority") or "").upper()
    rules = runtime.get("rules") or ["runtime activity"]
    rule = rules[0] if rules else "runtime activity"
    critical_tier = max_pri in _FALCO_CRITICAL_TIER
    alerts = runtime.get("alerts") or []

    # ESCALATE (+1): a critical-tier alert tied to a package this finding affects.
    if priority == "HIGH":
        hit = _attributed_alert(cve, alerts)
        if hit:
            proc = hit.get("process") or hit.get("exepath") or "a process"
            pkg = ", ".join(hit["matched"])
            tags = hit.get("tags") or []
            mitre = f" [MITRE {', '.join(tags)}]" if tags else ""
            return "CRITICAL", (
                f"escalated HIGH->CRITICAL: Falco {(hit.get('priority') or '').title()} "
                f"alert \"{hit.get('rule') or rule}\" on process {proc} -> package "
                f"{pkg}, which this CVE affects{mitre}"
            )
        if critical_tier:
            # Real runtime activity on the image, but nothing ties it to this
            # finding's packages. Record it; do not act on it.
            return priority, (
                f"runtime activity on this image (\"{rule}\") not attributable to this "
                f"finding's package(s) — recorded, no change"
            )

    # ANNOTATE only (no level change) for everything else.
    tier = "critical-tier" if critical_tier else "low-severity"
    return priority, (
        f"runtime activity observed on this image "
        f"(Falco {max_pri.title() or 'alert'}, {count} alert(s), {tier}); decision unchanged"
    )
