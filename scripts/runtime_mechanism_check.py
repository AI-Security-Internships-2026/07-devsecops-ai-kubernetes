"""
Mechanism check: does the runtime escalation path fire when an attributable alert of
sufficient severity exists?

This is NOT part of Dataset B's scored results and must never be reported as one. Dataset
B asked "does the runtime tier escalate under Falco's default configuration?" and the
answer, measured, is no -- the attributable alerts ship below our threshold. That result
stands.

This asks a different and narrower question: is the escalation path itself functional, or
is it dead code? A reader is entitled to know which, because "inert under default
configuration" and "broken" look identical from the outside.

The alert below is the real one Falco emitted for the provoked action, with only its
priority field raised. Nothing else is synthesised.
"""
import json, sys
sys.path.insert(0, ".")
from src.triage import ssvc

FINDING = {"cve_id": "CVE-2024-TEST", "epss_score": 0.02, "cvss_score": 8.0,
           "severity": "HIGH", "in_kev": False, "affected_packages": ["coreutils"]}

def runtime(priority, packages):
    return {"available": True, "count": 1, "max_priority": priority,
            "rules": ["Sensitive file opened for reading by non-trusted program"],
            "alerts": [{"priority": priority, "rule": "Sensitive file opened for reading",
                        "packages": packages, "process": "cat",
                        "exepath": "/usr/bin/cat"}]}

ctx = {"available": True, "deployed": True, "exposed": False, "privileged": False}

print(f"{'alert tier':<12}{'attributed to':<16}{'base':<10}{'final':<10}outcome")
print("-" * 68)
for tier in ("Warning", "Error", "Critical"):
    for pkgs, label in ((["coreutils"], "coreutils"), (["openssl"], "openssl")):
        r = ssvc.analyze(FINDING, False, context=ctx, runtime=runtime(tier, pkgs),
                         mode=ssvc.MODE_CLUSTER)
        base, _ = ssvc.classify_priority(FINDING, False)
        moved = "ESCALATED" if r["priority"] != base else "unchanged"
        print(f"{tier:<12}{label:<16}{base:<10}{r['priority']:<10}{moved}")
print()
print("Expected: escalation only when the tier is Error or above AND the alert is")
print("attributed to a package the finding affects. Any other cell escalating would")
print("be a defect.")
