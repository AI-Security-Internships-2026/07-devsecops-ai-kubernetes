#!/usr/bin/env python3
"""
collect_evidence.py - copy real pipeline output into experiments/evidence/ so a
reviewer can see the integration paths actually ran, not just that the code reads
correctly.

Why this exists
---------------
`.gitignore` excludes `experiments/results/*.json` and `*.md` wholesale, because that
directory is scratch space that gets rewritten on every run. The side effect is that
every artifact worth reviewing - the scan-cluster report, Falco alerts, the watcher
output, the cluster inventory - was uncommittable by default. Reviewers therefore had
no evidence that scan-cluster, the watcher or the escalation logic work end to end.

So evidence is curated rather than dumped: this script copies a known set of artifacts
into `experiments/evidence/`, which is NOT ignored, redacts the host details that
should not be in a public repo, and writes a MANIFEST that says which command produced
each file. Committing that directory is the deliverable.

Redaction
---------
Real output carries the operator's home path, the machine's hostname and (potentially)
an API key echoed into a log. All three are rewritten before anything is written to a
committed path. The redaction is deliberately blunt: it is easier to defend an
over-redacted artifact than to un-leak a key.

Usage
-----
    python scripts/collect_evidence.py                   # collect + redact + manifest
    python scripts/collect_evidence.py --label week10    # tag the run
    python scripts/collect_evidence.py --dry-run         # show what would be copied
"""

import argparse
import getpass
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "experiments" / "results"
EVIDENCE = REPO / "experiments" / "evidence"

# Artifacts worth reviewing, and the command that produces each. The description is
# written into the MANIFEST so a reviewer does not have to reverse-engineer the file.
ARTIFACTS = [
    ("scan_cluster_report.md", "python run.py scan-cluster --namespace default",
     "Cluster-wide triage: every running image, with Act/Attend/Track counts."),
    ("scan_cluster_report.json", "python run.py scan-cluster --namespace default",
     "Machine-readable form of the same cluster report."),
    ("cluster_inventory.json", "python run.py discover",
     "Pods, images, phase, exposure and privilege - the K8s context input."),
    ("falco_alerts.json", "python run.py falco-capture --live",
     "Normalised Falco runtime alerts as the tool consumes them."),
    ("falco_captured.jsonl", "bash scripts/falco_setup.sh capture 45",
     "Raw Falco JSONL exactly as the kernel probe emitted it."),
    ("cve_watch_alerts.md", "python run.py watch",
     "Fresh-CVE watcher output: SBOM x feed matches."),
    ("triage_run.json", "python run.py pipeline <image>",
     "Most recent single-image triage run."),
    ("eval.md", "python scripts/evaluate_triage.py experiments/results --out eval",
     "Evaluation tables: baselines, KEV recall, context/runtime effect, attribution."),
    ("eval.json", "python scripts/evaluate_triage.py experiments/results --out eval",
     "Machine-readable evaluation results."),
]

# Glob patterns collected in bulk (per-image outputs, generated policies).
PATTERNS = [
    ("triage_run_*.json", "python run.py pipeline <image>",
     "Per-image triage output - the file every evaluation number is computed from."),
    ("gatekeeper_*.yaml", "python run.py pipeline <image> --gatekeeper",
     "Generated OPA Gatekeeper policy (generate-only; nothing applies it)."),
]

# Key-shaped strings. Redacted before anything reaches a committed file - an
# over-redacted artifact is recoverable, a leaked key is not.
_SECRET_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),          # Google API key
    re.compile(r"gsk_[0-9A-Za-z]{20,}"),             # Groq
    re.compile(r"sk-[0-9A-Za-z]{20,}"),              # OpenAI-style
    # Terminator excludes JSON/YAML structure, so a redacted artifact stays
    # parseable - a reviewer has to be able to load the evidence.
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s\"',}\]]+"),
]


def redact(text: str, user: str, host: str) -> str:
    """Strip operator identity and anything key-shaped from artifact text."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: (m.group(1) + "********") if m.groups() else "********",
                       text)
    if user:
        text = re.sub(rf"/(?:home|Users)/{re.escape(user)}", "~", text)
        text = re.sub(rf"\b{re.escape(user)}\b", "<user>", text)
    if host:
        text = re.sub(rf"\b{re.escape(host)}\b", "<host>", text)
    # Any remaining absolute home path, whoever it belongs to.
    text = re.sub(r"/(?:home|Users)/[A-Za-z0-9._-]+", "~", text)
    return text


def copy_redacted(src: Path, dst: Path, user: str, host: str) -> str:
    """Copy one artifact through redaction. Returns a short status for the manifest."""
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"unreadable ({e})"
    cleaned = redact(text, user, host)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(cleaned, encoding="utf-8", newline="\n")
    note = "redacted" if cleaned != text else "verbatim"
    return f"{len(cleaned):,} bytes, {note}"


def summarize_triage(path: Path) -> str:
    """One-line headline for a triage_run file, so the manifest is skimmable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    s = data.get("summary", {})
    return (f"{data.get('container_image', '?')}: "
            f"{len(data.get('findings', []))} CVEs, "
            f"Act {s.get('critical_act', 0)}, Attend {s.get('high_attend', 0)}, "
            f"reduction {s.get('alert_reduction_pct', 0)}%")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--label", default="", help="tag for this collection (e.g. week10)")
    ap.add_argument("--results", default=str(RESULTS), help="source results directory")
    ap.add_argument("--out", default=str(EVIDENCE), help="destination evidence directory")
    ap.add_argument("--user", default="", help="username to redact (default: detected)")
    ap.add_argument("--host", default="", help="hostname to redact (default: detected)")
    ap.add_argument("--dry-run", action="store_true", help="list what would be copied")
    args = ap.parse_args()

    results, out = Path(args.results), Path(args.out)
    user = args.user or getpass.getuser()
    host = args.host or socket.gethostname().split(".")[0]

    if not results.is_dir():
        raise SystemExit(f"[!] No results directory at {results} - run the pipeline first.")

    found, missing = [], []
    for name, cmd, desc in ARTIFACTS:
        src = results / name
        (found if src.is_file() else missing).append((src, name, cmd, desc))
    for pattern, cmd, desc in PATTERNS:
        for src in sorted(results.glob(pattern)):
            if src.name == "triage_run.json":
                continue                        # already collected explicitly
            found.append((src, src.name, cmd, desc))

    if args.dry_run:
        print(f"Would collect {len(found)} artifact(s) into {out}:")
        for src, name, _, _ in found:
            print(f"  + {name}  ({src.stat().st_size:,} bytes)")
        for _, name, _, _ in missing:
            print(f"  - {name}  (not present - that stage has not been run)")
        return

    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Evidence — real pipeline output\n",
        f"Collected {stamp}" + (f" · label `{args.label}`" if args.label else "") + "\n",
        "Committed so the integration paths can be reviewed as *output*, not just as code.",
        "Every file is produced by the command listed beside it and passed through",
        "`scripts/collect_evidence.py`, which strips the operator's username, the",
        "hostname and anything key-shaped. Regenerate with:\n",
        "```bash\npython scripts/collect_evidence.py --label <tag>\n```\n",
        "| Artifact | Produced by | What it shows | Size |",
        "|---|---|---|---|",
    ]

    for src, name, cmd, desc in found:
        status = copy_redacted(src, out / name, user, host)
        extra = summarize_triage(src) if name.startswith("triage_run") else ""
        lines.append(f"| `{name}` | `{cmd}` | {desc}{(' — ' + extra) if extra else ''} "
                     f"| {status} |")
        print(f"[+] {name}  ({status})")

    if missing:
        lines.append("\n## Not collected\n")
        lines.append("These stages had not been run when evidence was collected, so no")
        lines.append("artifact exists. Absence here means *not run*, never *failed*.\n")
        for _, name, cmd, _ in missing:
            lines.append(f"- `{name}` — run `{cmd}`")
            print(f"[-] {name} (absent)")

    (out / "MANIFEST.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"\n[+] {len(found)} artifact(s) -> {out}")
    print(f"[+] Manifest: {out / 'MANIFEST.md'}")
    if missing:
        print(f"[*] {len(missing)} artifact(s) absent; see the manifest for the commands.")


if __name__ == "__main__":
    main()
