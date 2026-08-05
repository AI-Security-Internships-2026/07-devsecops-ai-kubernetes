"""
CVE-intelligence watcher agent — LangGraph.

Ties the intelligence layer together:
    collect  -> find SBOM x feed matches (our images hit by DB CVEs)
    enrich   -> add public-exploit signal (Exploit-DB)
    classify -> fresh-CVE rule (handles the EPSS-lag problem)
    report   -> write alerts to the DB + a markdown alert report

The fresh-CVE classification is pure and deterministic. LangGraph is imported lazily inside
build_watch_graph() so this module loads without it.

Fresh-CVE rule: a brand-new CVE has an artificially low EPSS for days,
so we lean on compensating signals — KEV, public exploit, high CVSS — to decide
urgency before EPSS matures.

Usage:
    python run.py watch                  # one-shot: a single collect->classify->report pass
    python run.py watch --interval 3600  # continuous: repeat every 3600s until Ctrl-C
    python run.py watch --status         # is a watcher running? show a summary
    python run.py watch --stop           # stop a running background watcher

By default this runs ONE pass (intended to be driven by an external scheduler such
as cron or a systemd timer). Pass --interval to loop it; run it in the background
(e.g. `nohup ... &` or the systemd unit in scripts/) and use --status to check on
it. A PID + status file (data/watcher.pid, data/watcher_status.json) back the
--status/--stop commands and keep a second watcher from double-starting.
"""

import json
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from src import config
from src.database import db
from src.database.matcher import find_matches


# ---------------------------------------------------------------------------
# Pure classification
# ---------------------------------------------------------------------------

def classify_match(match: dict, exploit_exists: bool = False) -> dict:
    """
    Classify a fresh-CVE match. Returns {priority, reason}.

    FRESH-CRITICAL : KEV, or public exploit, or CVSS >= 9
    FRESH-WATCH    : EPSS >= 0.1, or CVSS >= 7
    FRESH-INFO     : everything else that still affects us
    """
    cvss = match.get("cvss_score") or 0.0
    epss = match.get("epss_score")
    in_kev = bool(match.get("in_kev"))

    reasons = []
    if in_kev:
        reasons.append("in CISA KEV")
    if exploit_exists:
        reasons.append("public exploit exists")
    if cvss >= 9.0:
        reasons.append(f"CVSS {cvss:.1f}")

    if reasons:
        return {"priority": "FRESH-CRITICAL", "reason": "; ".join(reasons)}

    if (epss is not None and epss >= 0.1) or cvss >= 7.0:
        detail = f"EPSS {epss:.3f}" if epss is not None else f"CVSS {cvss:.1f}"
        return {"priority": "FRESH-WATCH", "reason": f"elevated risk ({detail})"}

    epss_note = "EPSS pending" if epss is None else f"EPSS {epss:.3f}"
    return {"priority": "FRESH-INFO", "reason": f"affects deployed image ({epss_note})"}


# ---------------------------------------------------------------------------
# Graph state + nodes
# ---------------------------------------------------------------------------

class WatchState(TypedDict):
    matches: list[dict]
    exploit_lookup: object
    classified: list[dict]
    report_path: str


def collect_node(state: WatchState) -> dict:
    with db.get_conn() as conn:
        matches = find_matches(conn)
    print(f"[+] Watcher: {len(matches)} SBOM x feed matches")
    return {"matches": matches}


def enrich_node(state: WatchState) -> dict:
    """Attach a public-exploit lookup (best-effort; None if unavailable)."""
    lookup = None
    try:
        from src.enrichment.exploit_db import make_exploit_lookup
        lookup = make_exploit_lookup()
    except Exception as e:
        print(f"[*] Exploit-DB unavailable ({e})")
    return {"exploit_lookup": lookup}


def classify_node(state: WatchState) -> dict:
    lookup = state.get("exploit_lookup")
    classified = []
    for m in state["matches"]:
        exploit_exists = False
        if lookup:
            try:
                exploit_exists = bool(lookup(m["cve_id"]))
            except Exception:
                exploit_exists = False
        verdict = classify_match(m, exploit_exists)
        classified.append({**m, **verdict, "exploit_exists": exploit_exists})
    counts: dict[str, int] = {}
    for c in classified:
        counts[c["priority"]] = counts.get(c["priority"], 0) + 1
    print(f"[+] Watcher classification: {counts}")
    return {"classified": classified}


def report_node(state: WatchState) -> dict:
    classified = state["classified"]

    # persist alerts
    with db.get_conn() as conn:
        for c in classified:
            db.insert_alert(conn, {
                "cve_id": c["cve_id"],
                "image": c["image"],
                "package_name": c["package_name"],
                "reason": c["reason"],
                "priority": c["priority"],
                "needs_verification": True,
            })
        conn.commit()

    # markdown alert report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    order = {"FRESH-CRITICAL": 0, "FRESH-WATCH": 1, "FRESH-INFO": 2}
    classified.sort(key=lambda c: order.get(c["priority"], 3))

    md = [f"# CVE Watch Alerts\n", f"**Generated:** {now}",
          f"**Matches:** {len(classified)}\n",
          "> Early-warning matches (SBOM x CVE feeds). Flagged `needs verification` — "
          "distro backports may not bump versions; confirm with a full scan.\n"]
    md.append("| Priority | CVE | Image | Package | Installed | Fixed | Reason |")
    md.append("|----------|-----|-------|---------|-----------|-------|--------|")
    for c in classified:
        md.append(
            f"| {c['priority']} | {c['cve_id']} | {c['image']} | {c['package_name']} | "
            f"{c.get('installed_version','')} | {c.get('version_fixed') or '—'} | {c['reason']} |"
        )

    config.ensure_dirs()
    report_path = config.RESULTS_DIR / "cve_watch_alerts.md"
    report_path.write_text("\n".join(md), encoding="utf-8")
    print(f"[+] Watch report saved: {report_path}")
    return {"report_path": str(report_path)}


def build_watch_graph():
    """Build the watcher StateGraph (langgraph imported lazily)."""
    from langgraph.graph import END, StateGraph
    g = StateGraph(WatchState)
    g.add_node("collect", collect_node)
    g.add_node("enrich", enrich_node)
    g.add_node("classify", classify_node)
    g.add_node("report", report_node)
    g.set_entry_point("collect")
    g.add_edge("collect", "enrich")
    g.add_edge("enrich", "classify")
    g.add_edge("classify", "report")
    g.add_edge("report", END)
    return g


def _watch_once() -> dict:
    """Run a single collect -> enrich -> classify -> report pass."""
    print(f"\n{'='*70}\nCVE INTELLIGENCE WATCHER\n{'='*70}")
    app = build_watch_graph().compile()
    state: WatchState = {"matches": [], "exploit_lookup": None, "classified": [], "report_path": ""}
    final = app.invoke(state)

    crit = sum(1 for c in final["classified"] if c["priority"] == "FRESH-CRITICAL")
    print(f"\n{'='*70}\nWATCH COMPLETE — {len(final['classified'])} matches, {crit} FRESH-CRITICAL\n{'='*70}")
    return final


# ---------------------------------------------------------------------------
# Background-service plumbing (PID + status files)
#
# Stdlib-only and deliberately OS-neutral in the core logic so multi-arch /
# multi-OS support can drop in later. The systemd unit in scripts/ is one optional
# way to run this as a managed background service on Linux; it is not required.
# ---------------------------------------------------------------------------

def _pid_path() -> Path:
    return config.DATA_DIR / "watcher.pid"


def _status_path() -> Path:
    return config.DATA_DIR / "watcher_status.json"


def _pid_alive(pid: int) -> bool:
    """Best-effort, portable 'is this pid alive?' check."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)          # POSIX: signal 0 only checks existence
    except ProcessLookupError:
        return False
    except PermissionError:
        return True              # exists but owned by someone else
    except OSError:
        return False             # e.g. not supported on this OS -> not verifiable
    return True


def _running_pid() -> int | None:
    """Pid of a live watcher from the pid file, clearing a stale file."""
    pp = _pid_path()
    if not pp.exists():
        return None
    try:
        pid = int(pp.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None
    if _pid_alive(pid):
        return pid
    try:
        pp.unlink()
    except OSError:
        pass
    return None


def _write_pid() -> None:
    config.ensure_dirs()
    _pid_path().write_text(str(os.getpid()), encoding="utf-8")


def _clear_pid() -> None:
    pp = _pid_path()
    try:
        if pp.exists() and pp.read_text(encoding="utf-8").strip() == str(os.getpid()):
            pp.unlink()
    except OSError:
        pass


def _write_status(final: dict, started_at: str, passes: int) -> None:
    classified = (final or {}).get("classified", [])
    fresh_crit = sum(1 for c in classified if c.get("priority") == "FRESH-CRITICAL")
    status = {
        "pid": os.getpid(),
        "started_at": started_at,
        "last_run": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "passes": passes,
        "total_matches": len(classified),
        "fresh_critical": fresh_crit,
    }
    config.ensure_dirs()
    _status_path().write_text(json.dumps(status, indent=2), encoding="utf-8")


def _print_status() -> None:
    pid = _running_pid()
    sp = _status_path()
    if sp.exists():
        s = json.loads(sp.read_text(encoding="utf-8"))
        print(f"[*] Watcher status: {'RUNNING' if pid else 'stopped'}")
        if pid:
            print(f"    pid:         {pid}")
        print(f"    started:     {s.get('started_at', '-')}")
        print(f"    last pass:   {s.get('last_run', '-')}")
        print(f"    passes:      {s.get('passes', 0)}")
        print(f"    matches:     {s.get('total_matches', 0)} "
              f"({s.get('fresh_critical', 0)} FRESH-CRITICAL)")
    else:
        print("[*] Watcher status: no run recorded yet.")
    if not pid:
        print("[*] No live watcher process.")


def _stop_running() -> None:
    pid = _running_pid()
    if not pid:
        print("[*] No running watcher to stop.")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"[+] Sent stop signal to watcher (pid {pid}).")
    except OSError as e:
        print(f"[!] Could not stop pid {pid}: {e}")


def run_watch(interval: int | None = None, status: bool = False, stop: bool = False) -> dict:
    """
    Run the watcher, or query/stop a background one.

    - status=True : print whether a watcher is running + a summary, then return.
    - stop=True   : signal a running background watcher to stop, then return.
    - interval=None (default): one pass (suitable for cron / a systemd timer).
    - interval=N  : run continuously every N seconds until Ctrl-C or `--stop`.

    While running it writes data/watcher.pid + data/watcher_status.json. If a live
    watcher is already running, a new invocation prints its status and refuses to
    start a second one.
    """
    db.init_db()

    if status:
        _print_status()
        return {}
    if stop:
        _stop_running()
        return {}

    existing = _running_pid()
    if existing:
        print(f"[*] A watcher is already running (pid {existing}); not starting another.")
        _print_status()
        return {}

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_pid()
    passes = 0
    final: dict = {}
    try:
        if interval is None:
            passes = 1
            final = _watch_once()
            _write_status(final, started_at, passes)
            return final
        print(f"[*] Continuous watch: repeating every {interval}s (Ctrl-C to stop)")
        while True:
            passes += 1
            final = _watch_once()
            _write_status(final, started_at, passes)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Watcher stopped.")
        return final
    finally:
        _clear_pid()


if __name__ == "__main__":
    run_watch()
