#!/usr/bin/env python3
"""
Dataset B -- controlled Kubernetes scenarios (issues #21, #24, #25).

Four stages, deliberately separable so that only one of them needs a cluster:

    render    scenarios.yaml -> Kubernetes manifests            (no cluster)
    deploy    apply the manifests and wait for readiness        (cluster)
    collect   scan + triage each scenario, save decisions       (cluster)
    score     compare against the pre-registered expectations   (no cluster)

Splitting render from deploy means the manifests can be reviewed and committed before the
VM session, and splitting collect from score means a long capture is never at risk of
being lost to a scoring bug.

    python scripts/build_dataset_b.py render
    python scripts/build_dataset_b.py deploy
    python scripts/build_dataset_b.py collect --runtime
    python scripts/build_dataset_b.py score
    python scripts/build_dataset_b.py teardown
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.dataset import controlled                                   # noqa: E402

OUT_DIR = controlled.DATASET_B_DIR
MANIFEST_PATH = OUT_DIR / "manifests.yaml"
DECISIONS_DIR = OUT_DIR / "decisions"
RESULTS_PATH = OUT_DIR / "results.json"


def sh(args, check=False, timeout=300):
    """Run a command, returning (rc, stdout, stderr) rather than raising by default."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            print(f"[!] {' '.join(args)}\n{p.stderr.strip()}")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{args[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


# --------------------------------------------------------------------- render

def cmd_render(args):
    scenarios = controlled.load_scenarios()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(controlled.render_manifests(scenarios), encoding="utf-8")

    print(f"[+] {len(scenarios)} scenarios -> {MANIFEST_PATH}")
    print(f"\n{'scenario':<24}{'image':<20}{'deployed':>9}{'exposed':>9}"
          f"{'priv':>6}  expect")
    print("-" * 78)
    for s in scenarios:
        print(f"{s.name:<24}{s.image:<20}{str(s.deployed):>9}"
              f"{(s.exposure_type or str(s.exposed)):>9}{str(s.privileged):>6}  "
              f"{s.expect}")

    runtime = [s for s in scenarios if s.runtime_actions]
    if runtime:
        print(f"\n[*] {len(runtime)} scenario(s) provoke runtime behaviour; "
              f"collect with --runtime")
    print("\n[*] No cluster was contacted. Review the manifests, then: deploy")
    return 0


# --------------------------------------------------------------------- deploy

def cmd_deploy(args):
    if not MANIFEST_PATH.exists():
        print("[!] manifests not rendered yet: python scripts/build_dataset_b.py render")
        return 1

    rc, out, err = sh(["kubectl", "apply", "-f", str(MANIFEST_PATH)])
    if rc != 0:
        print(f"[!] kubectl apply failed:\n{err.strip()}")
        return 1
    print(out.strip())

    scenarios = [s for s in controlled.load_scenarios() if s.deployed]
    print(f"\n[*] waiting for {len(scenarios)} workload(s) to become ready "
          f"(timeout {args.timeout}s each)")

    not_ready = []
    for s in scenarios:
        rc, _, err = sh(["kubectl", "rollout", "status",
                         f"deployment/{s.workload_name}", "-n", s.namespace,
                         f"--timeout={args.timeout}s"], timeout=args.timeout + 30)
        status = "ready" if rc == 0 else "NOT READY"
        print(f"    {s.workload_name:<28} {status}")
        if rc != 0:
            not_ready.append(s.workload_name)

    if not_ready:
        print(f"\n[!] {len(not_ready)} workload(s) not ready. Image pulls on a fresh "
              f"node are\n    the usual cause; check: kubectl describe pod -n "
              f"{scenarios[0].namespace}")
        return 1

    print("\n[+] all workloads ready. Next: collect")
    return 0


# -------------------------------------------------------------------- collect

def cmd_collect(args):
    """
    Scan and triage every scenario, saving one decision file each.

    The pipeline is invoked exactly as an operator would invoke it, rather than by
    calling the engine directly: the thing under test includes the context provider and
    the scanner integration, and bypassing them would test less than the paper claims.
    """
    scenarios = controlled.load_scenarios()
    DECISIONS_DIR.mkdir(parents=True, exist_ok=True)

    if args.runtime:
        rc, _, _ = sh(["kubectl", "get", "ns", "falco"])
        if rc != 0:
            print("[!] --runtime given but the falco namespace does not exist.")
            print("    Install it first: bash scripts/falco_setup.sh install")
            return 1

    collected, failed = [], []
    for s in scenarios:
        print(f"\n=== {s.name} ({s.image}) " + "=" * (44 - len(s.name)))

        if s.runtime_actions and args.runtime:
            provoke_runtime(s)

        cmd = [sys.executable, "run.py", "pipeline", s.image,
               "--json", str(DECISIONS_DIR / f"{s.name}.json")]
        if s.runtime_actions and args.runtime:
            cmd.append("--runtime")
        # A not-deployed scenario must still be scanned *in cluster mode*: the finding
        # under test is precisely that the cluster reports the image as absent.
        rc, out, err = sh(cmd, timeout=args.timeout)
        if rc != 0:
            print(f"[!] pipeline failed for {s.name}: {(err or out).strip()[:400]}")
            failed.append(s.name)
            continue
        collected.append(s.name)
        print(f"[+] decisions -> {DECISIONS_DIR / (s.name + '.json')}")

    meta = {
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenarios_collected": collected,
        "scenarios_failed": failed,
        "runtime_enabled": bool(args.runtime),
        "git_commit": sh(["git", "rev-parse", "HEAD"])[1].strip(),
    }
    (OUT_DIR / "collection.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"\n[+] {len(collected)} collected, {len(failed)} failed")
    if failed:
        print(f"[!] failed: {', '.join(failed)}")
        return 1
    print("[*] Next: score")
    return 0


def provoke_runtime(scenario):
    """
    Trigger the declared runtime behaviour inside the scenario's pod.

    Actions are benign by construction -- reading a file, starting a shell that exits
    immediately. They exist to make Falco emit an alert with a known, labelled cause, so
    attribution has ground truth to be measured against. Nothing is exploited.
    """
    rc, out, _ = sh(["kubectl", "get", "pods", "-n", scenario.namespace,
                     "-l", f"app={scenario.workload_name}",
                     "-o", "jsonpath={.items[0].metadata.name}"])
    pod = out.strip()
    if rc != 0 or not pod:
        print(f"[!] no pod found for {scenario.name}; runtime actions skipped")
        return

    for action in scenario.runtime_actions:
        cmd = action.get("command") or []
        label = action.get("action", "action")
        print(f"[*] provoking {label!r} in {pod} -> expect Falco rule "
              f"{action.get('expect_falco_rule')!r}")
        sh(["kubectl", "exec", "-n", scenario.namespace, pod, "--", *cmd], timeout=60)

    # Falco buffers and the pipeline reads the alert stream afterwards, so a short
    # settle beats racing the alert out of the pod's stdout.
    time.sleep(5)


# ---------------------------------------------------------------------- score

def cmd_score(args):
    scenarios = controlled.load_scenarios()
    decisions = {}
    for s in scenarios:
        path = DECISIONS_DIR / f"{s.name}.json"
        if not path.exists():
            print(f"[!] missing decisions for {s.name}; run collect first")
            return 1
        decisions[s.name] = priorities_from(json.loads(path.read_text(encoding="utf-8")))

    print(f"\nDataset B -- {len(scenarios)} scenarios "
          f"({sum(1 for s in scenarios if s.is_reference)} references)")
    for s in scenarios:
        if s.is_reference:
            print(f"    reference {s.name:<18} {s.image:<18} "
                  f"{len(decisions[s.name])} findings")
    print(f"\n{'scenario':<24}{'expect':<14}{'n':>6}{'as expected':>13}{'wrong':>8}"
          f"{'flat':>7}{'rate':>8}")
    print("-" * 80)

    results = []
    for s in scenarios:
        if s.is_reference:
            continue
        r = controlled.score(decisions[s.compare_to], decisions[s.name], s)
        results.append(r)
        rate = "n/a" if r["agreement_rate"] is None else f"{r['agreement_rate']:.1%}"
        print(f"{r['scenario']:<24}{r['expected_direction']:<14}"
              f"{r['findings_compared']:>6}{r['moved_as_expected']:>13}"
              f"{r['wrong_direction']:>8}{r['unchanged']:>7}{rate:>8}")
        if r["exempt_findings_compared"]:
            er = ("n/a" if r["exempt_agreement_rate"] is None
                  else f"{r['exempt_agreement_rate']:.1%}")
            print(f"{'  └ exempt CVEs':<24}{r['exempt_expected_direction']:<14}"
                  f"{r['exempt_findings_compared']:>6}"
                  f"{r['exempt_moved_as_expected']:>13}"
                  f"{r['exempt_wrong_direction']:>8}{r['exempt_unchanged']:>7}{er:>8}")
        if r["exempt_cves_missing"]:
            print(f"    [!] exempt CVEs absent from the scan: "
                  f"{', '.join(r['exempt_cves_missing'])}")

    wrong = [r for r in results
             if r["wrong_direction"] or r["exempt_wrong_direction"]]
    if wrong:
        print(f"\n[!] {len(wrong)} scenario(s) moved findings the WRONG way. This is a "
              f"result, not\n    a crash -- report it. Scenarios: "
              f"{', '.join(r['scenario'] for r in wrong)}")

    RESULTS_PATH.write_text(json.dumps(
        {"scored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
         "results": results}, indent=2), encoding="utf-8")
    print(f"\n[+] {RESULTS_PATH}")
    return 0


def priorities_from(report: dict) -> dict:
    """cve_id -> priority, from a pipeline JSON report."""
    out = {}
    for finding in report.get("findings", report.get("results", [])) or []:
        cve_id = finding.get("cve_id") or finding.get("id")
        priority = finding.get("priority") or finding.get("severity")
        if cve_id and priority:
            # A CVE can appear once per affected package; the scenario comparison is
            # per CVE, so keep the highest priority seen for it.
            prev = out.get(cve_id)
            ladder = controlled._LADDER
            if prev is None or (priority in ladder and prev in ladder
                                and ladder.index(priority) > ladder.index(prev)):
                out[cve_id] = priority
    return out


# ------------------------------------------------------------------- teardown

def cmd_teardown(args):
    namespaces = sorted({s.namespace for s in controlled.load_scenarios()})
    for ns in namespaces:
        rc, out, err = sh(["kubectl", "delete", "namespace", ns, "--wait=false"])
        print(out.strip() or err.strip())
    print("[+] teardown requested (running in the background)")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("render", help="scenarios.yaml -> manifests (no cluster)")

    p = sub.add_parser("deploy", help="apply manifests and wait for readiness")
    p.add_argument("--timeout", type=int, default=180)

    p = sub.add_parser("collect", help="scan + triage every scenario")
    p.add_argument("--runtime", action="store_true",
                   help="provoke the declared runtime actions and read Falco alerts")
    p.add_argument("--timeout", type=int, default=900)

    sub.add_parser("score", help="compare against the pre-registered expectations")
    sub.add_parser("teardown", help="delete the scenario namespaces")

    args = ap.parse_args()
    return {"render": cmd_render, "deploy": cmd_deploy, "collect": cmd_collect,
            "score": cmd_score, "teardown": cmd_teardown}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
