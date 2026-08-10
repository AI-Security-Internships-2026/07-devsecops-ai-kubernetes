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
    True if `value` names an existing file.

    Guarded because this is also called with raw alert text: a long or otherwise
    invalid path makes Path.exists() raise OSError (notably on Windows, where the
    path-length limit applies) or ValueError (embedded NUL) instead of returning
    False. Either way it simply isn't a file.
    """
    try:
        return Path(value).exists()
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
        try:
            chunks.append(core.read_namespaced_pod_log(
                name=p.metadata.name, namespace=namespace, since_seconds=since_seconds))
        except Exception as e:
            print(f"[*] Could not read logs of {p.metadata.name} ({e})")
    return parse_falco_stream("\n".join(chunks))


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
        print("[*] No alerts (empty stream, or Falco not producing JSON output yet).")
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
