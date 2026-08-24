"""
Falco runtime alert reader.

Falco watches the cluster at the kernel level (eBPF) and emits runtime alerts
(shell spawned in a container, unexpected file access, etc.). This module reads
Falco's JSON output stream and normalizes it into simple records, and can group
alerts by the container image they came from.

This is the FIRST slice of the roadmap's "Kubernetes runtime reachability"
milestone: capture the runtime signal now; wiring it into the SSVC score (an
image with real runtime activity gets a principled urgency bump) is the next step.

Honest limitation: Falco maps alerts to pods/containers, not to CVEs. The link to
a finding is via the pod's image (image-level runtime context), not per-CVE
reachability.

Usage:
    python run.py falco-capture <falco_output.json>     # parse a captured file
    python run.py falco-capture --live                  # pull straight from the cluster (no need to provide runtime report file)
"""

import json
import sys
from pathlib import Path

from src import config
from src.context.k8s_context import images_match


def _image_from_fields(fields: dict) -> str:
    """Reconstruct 'repo:tag' from Falco output_fields, if present."""
    repo = fields.get("container.image.repository") or ""
    tag = fields.get("container.image.tag") or ""
    if repo and tag:
        return f"{repo}:{tag}"
    return repo


def _is_existing_file(value: str) -> bool:
    """
    True if `value` names an existing regular file.

    Two guards, both hit in practice:
      - `is_file()`, not `exists()`: Path("") normalises to Path(".") whose
        exists() is True, so an empty stream would try to read the current
        directory (IsADirectoryError on Linux, PermissionError on Windows).
      - try/except: raw alert text longer than the path limit makes Path() raise
        OSError (Windows) or ValueError (embedded NUL) rather than returning False.
    """
    if not value or not value.strip():
        return False
    try:
        return Path(value).is_file()
    except (OSError, ValueError):
        return False


def parse_falco_stream(path_or_text: str) -> list[dict]:
    """
    Parse Falco JSON output (JSONL — one JSON alert per line) into normalized
    records. Accepts a file path or raw text. Blank/malformed lines are skipped.
    """
    if _is_existing_file(path_or_text):
        text = Path(path_or_text).read_text(encoding="utf-8", errors="ignore")
    else:
        text = path_or_text

    alerts = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        fields = obj.get("output_fields", {}) or {}
        alerts.append({
            "time": obj.get("time") or obj.get("evt.time"),
            "rule": obj.get("rule", ""),
            "priority": obj.get("priority", ""),
            "output": obj.get("output", ""),
            "namespace": fields.get("k8s.ns.name", ""),
            "pod": fields.get("k8s.pod.name", ""),
            "container": fields.get("container.name", ""),
            "image": _image_from_fields(fields),
            "process": fields.get("proc.name", ""),
        })
    return alerts


def alerts_for_image(alerts: list[dict], image: str) -> list[dict]:
    """Return the alerts whose container image matches `image` (registry-agnostic)."""
    return [a for a in alerts if a.get("image") and images_match(image, a["image"])]


def summarize(alerts: list[dict]) -> dict:
    """Small summary: totals, by-priority, by-image (for the capture printout)."""
    by_priority: dict[str, int] = {}
    by_image: dict[str, int] = {}
    for a in alerts:
        by_priority[a["priority"]] = by_priority.get(a["priority"], 0) + 1
        if a.get("image"):
            by_image[a["image"]] = by_image.get(a["image"], 0) + 1
    return {"total": len(alerts), "by_priority": by_priority, "by_image": by_image}


def _falco_container_name(pod) -> str | None:
    """
    Pick the container whose stdout carries the alerts.

    The Falco Helm chart runs a multi-container DaemonSet (falco plus
    falco-driver-loader / falcoctl-artifact-install / falcoctl-artifact-follow), and
    the logs API returns HTTP 400 unless a container is named. Prefer the container
    literally called "falco", else the first one.
    """
    containers = list(getattr(pod.spec, "containers", None) or [])
    if not containers:
        return None
    for c in containers:
        if c.name == "falco":
            return c.name
    return containers[0].name


def capture_from_cluster(namespace: str = "falco",
                         selector: str = "app.kubernetes.io/name=falco",
                         since_seconds: int | None = None) -> list[dict]:
    """
    Pull Falco alerts straight from the running cluster — the Falco DaemonSet pods'
    JSON stdout — via the kubernetes client, and normalize them.

    Returns [] if the kubernetes package, the cluster, or the Falco pods aren't
    reachable (callers degrade gracefully).
    """
    try:
        from kubernetes import client, config as kube_config
    except Exception:
        print("[*] kubernetes package not installed — cannot capture Falco from the cluster")
        return []
    try:
        try:
            kube_config.load_incluster_config()
        except Exception:
            kube_config.load_kube_config()
        core = client.CoreV1Api()
        pods = core.list_namespaced_pod(namespace, label_selector=selector).items
    except Exception as e:
        print(f"[*] Could not reach Falco pods in namespace '{namespace}' ({e})")
        return []
    if not pods:
        print(f"[*] No Falco pods found in namespace '{namespace}' (selector '{selector}')")
        return []

    chunks = []
    for p in pods:
        container = _falco_container_name(p)
        try:
            chunks.append(core.read_namespaced_pod_log(
                name=p.metadata.name, namespace=namespace, container=container,
                since_seconds=since_seconds))
        except Exception as e:
            print(f"[*] Could not read logs of {p.metadata.name}/{container} ({e})")
    text = "\n".join(c for c in chunks if c)
    if not text.strip():
        print("[*] Falco pods returned no log output at all.")
        _explain_no_alerts()
        return []

    alerts = parse_falco_stream(text)
    if not alerts:
        # Distinguish "Falco said nothing" from "Falco is talking, but not in JSON".
        # Both surface as zero alerts, but they need opposite fixes.
        n_lines = sum(1 for line in text.splitlines() if line.strip())
        print(f"[*] Read {n_lines} log line(s) from Falco but parsed 0 JSON alerts.")
        _explain_no_alerts()
    return alerts


def _explain_no_alerts() -> None:
    """
    A zero-alert capture is ambiguous, so name the three preconditions rather than
    letting the caller guess. Ordered by how often each one is actually the cause:
    an idle cluster produces no alerts, and that is normal, healthy Falco behaviour.
    """
    print("    Three things must all hold for a live capture to return alerts:")
    print("      1. a rule must have FIRED   — Falco is silent on an idle cluster")
    print("      2. json_output must be true — we cannot parse Falco's text format")
    print("      3. the driver must be loaded — no driver means no syscall events")
    print("    Check all three, in that order:  bash scripts/falco_setup.sh verify")


def _save_alerts(alerts: list[dict]) -> Path:
    """Summarize + persist normalized alerts to the results dir; print a breakdown."""
    summary = summarize(alerts)
    config.ensure_dirs()
    out_path = config.RESULTS_DIR / "falco_alerts.json"
    out_path.write_text(json.dumps({"summary": summary, "alerts": alerts}, indent=2),
                        encoding="utf-8")

    print(f"[+] Parsed {summary['total']} Falco alerts -> {out_path}")
    print(f"    by priority: {summary['by_priority']}")
    if summary["by_image"]:
        print(f"    by image:    {summary['by_image']}")
    if not alerts:
        print("[*] No alerts parsed — see the checks above before treating this as a bug.")
    return out_path


def run(falco_output_path: str) -> Path:
    """Parse a Falco output FILE and save normalized alerts to the results dir."""
    return _save_alerts(parse_falco_stream(falco_output_path))


def run_live(namespace: str = "falco", since_seconds: int | None = None) -> Path:
    """Capture Falco alerts LIVE from the cluster and save them (no manual file)."""
    print(f"[*] Capturing Falco alerts live from namespace '{namespace}'...")
    return _save_alerts(capture_from_cluster(namespace=namespace, since_seconds=since_seconds))


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py falco-capture <falco_output.json>")
        sys.exit(1)
    run(sys.argv[1])


if __name__ == "__main__":
    main()
