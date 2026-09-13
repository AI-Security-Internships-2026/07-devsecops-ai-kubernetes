"""
Dataset A — large-scale historical vulnerability benchmark (issue #21).

The question this dataset answers is deliberately narrow: *given only what was knowable
on date T, which vulnerabilities would each prioritization method have flagged, and
which of those went on to acquire high-confidence exploitation evidence?*

Getting that right is mostly about what is excluded.

**Features are frozen at T.** EPSS comes from the daily archive published on T, not from
today. Exploit evidence counts only exploits published on or before T. CVEs published
after T are dropped entirely — they could not have been prioritized at T.

**Labels come only from after T.** A CVE already in KEV at T is not a prediction target:
its exploitation was already known and was an *input* to the decision, so scoring it as a
successful prediction would reward a method for reading what it was handed. Those rows
are retained and flagged `eligible=False` so the manifest can report how many were
excluded, rather than silently shrinking the population.

**Negatives are not asserted.** A CVE that did not enter KEV within the window is
labelled unknown, not "not exploited" — KEV is high-confidence positive evidence, not a
complete census of exploitation. Metrics that need a negative class must state the
operational proxy they use; the dataset itself does not pretend to know.

Three snapshots are built with 30/60/90-day outcome windows. The windows share one
feature freeze per snapshot, so they cost nothing extra to produce and show how
predictive quality decays with horizon. The same CVE recurring across snapshots is
*correlated*, not independent — anything resampling these rows must cluster by CVE.
"""

import csv
import gzip
import json
import re
from datetime import date, datetime, timedelta
from pathlib import Path

from src import config
from src.dataset import nvd_cvss, sources

# Snapshots: spread over a year, each with its full 90-day outcome window elapsed.
DEFAULT_SNAPSHOTS = (date(2025, 9, 1), date(2026, 1, 1), date(2026, 6, 1))
DEFAULT_WINDOWS = (30, 60, 90)

DATASETS_DIR = config.ROOT / "datasets"
HISTORICAL_DIR = DATASETS_DIR / "historical"

FIELDS = [
    "cve_id", "snapshot_date",
    # features, all as known at snapshot_date
    "epss_score", "epss_percentile", "cvss_score", "cvss_severity", "cvss_version",
    "published", "public_exploit_at_snapshot", "kev_at_snapshot",
    # outcome labels, all strictly after snapshot_date
    "later_kev_30d", "later_kev_60d", "later_kev_90d",
    "kev_date_added", "eligible",
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def exploit_dates() -> dict[str, date]:
    """
    {cve_id: earliest public exploit publication date} from the Exploit-DB index.

    The existing exploit loader answers only "does an exploit exist *now*", which cannot
    be used as a point-in-time feature: an exploit published after T would leak future
    information into a decision made at T. The `date_published` column gives the earliest
    date per CVE, so the feature can be evaluated as of any snapshot.
    """
    from src.enrichment.exploit_db import CACHE_PATH, _download_csv

    if not CACHE_PATH.exists():
        text = _download_csv()
        if not text:
            print("[!] Exploit-DB unavailable; public_exploit_at_snapshot will be False")
            return {}
        CACHE_PATH.write_text(text, encoding="utf-8")

    out: dict[str, date] = {}
    with open(CACHE_PATH, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            raw = (row.get("date_published") or "").strip()[:10]
            if not raw:
                continue
            try:
                published = datetime.strptime(raw, "%Y-%m-%d").date()
            except ValueError:
                continue
            # `codes` holds the CVE/OSVDB references for the entry.
            for cve in _CVE_RE.findall(row.get("codes") or ""):
                cve = cve.upper()
                if cve not in out or published < out[cve]:
                    out[cve] = published
    return out


def build_snapshot(snapshot: date, windows=DEFAULT_WINDOWS, *, cvss_index=None,
                   kev_dates=None, exploits=None, epss=None) -> tuple[list[dict], dict]:
    """
    Build every row for one snapshot, plus its statistics.

    Returns (rows, stats). Every input can be injected: a multi-snapshot build loads the
    CVSS index and KEV catalog once rather than per snapshot, and the unit tests supply
    all four so the assembly logic is exercised without touching the network.
    """
    cvss_index = nvd_cvss.load_index() if cvss_index is None else cvss_index
    kev_dates = sources.load_kev_dates() if kev_dates is None else kev_dates
    exploits = exploit_dates() if exploits is None else exploits
    epss = sources.load_epss_snapshot(snapshot) if epss is None else epss
    rows: list[dict] = []
    skipped_unpublished = skipped_no_cvss = 0

    for cve, scores in epss.items():
        record = cvss_index.get(cve)
        if record is None:
            skipped_no_cvss += 1
            continue
        if not nvd_cvss.published_before(record, snapshot):
            skipped_unpublished += 1
            continue

        exploit_date = exploits.get(cve)
        labels = sources.kev_labels(kev_dates, cve, snapshot, windows)

        row = {
            "cve_id": cve,
            "snapshot_date": snapshot.isoformat(),
            "epss_score": round(scores["epss"], 5),
            "epss_percentile": round(scores["percentile"], 5),
            "cvss_score": record["cvss_score"],
            "cvss_severity": record["cvss_severity"],
            "cvss_version": record["cvss_version"],
            "published": record["published"],
            "public_exploit_at_snapshot": bool(exploit_date and exploit_date <= snapshot),
            "kev_at_snapshot": labels["kev_at_snapshot"],
            "kev_date_added": labels["kev_date_added"],
            "eligible": labels["eligible"],
        }
        for n in windows:
            row[f"later_kev_{n}d"] = labels[f"later_kev_{n}d"]
        rows.append(row)

    eligible = [r for r in rows if r["eligible"]]

    # How many KEV entrants inside the window never made it into the population, and
    # why. This is not bookkeeping: a CVE published after T did not exist when the
    # prioritization decision was made, so no method operating on the population at T
    # could have flagged it. Reporting it bounds what any method can achieve on this
    # task, and stops the unreachable entrants being mistaken for missed detections.
    in_population = {r["cve_id"] for r in rows}
    unreachable = {f"{n}d": {"published_after_snapshot": 0, "absent_from_epss": 0}
                   for n in windows}
    for n in windows:
        horizon = snapshot + timedelta(days=n)
        for cve, added in kev_dates.items():
            if not (snapshot < added <= horizon) or cve in in_population:
                continue
            record = cvss_index.get(cve)
            if record and not nvd_cvss.published_before(record, snapshot):
                unreachable[f"{n}d"]["published_after_snapshot"] += 1
            else:
                unreachable[f"{n}d"]["absent_from_epss"] += 1

    stats = {
        "snapshot_date": snapshot.isoformat(),
        "epss_model_version": _model_version(snapshot),
        "cves_in_epss": len(epss),
        "rows": len(rows),
        "skipped_published_after_snapshot": skipped_unpublished,
        "skipped_no_cvss_record": skipped_no_cvss,
        "kev_at_snapshot": sum(1 for r in rows if r["kev_at_snapshot"]),
        "eligible": len(eligible),
        "positives": {f"{n}d": sum(1 for r in eligible if r[f"later_kev_{n}d"])
                      for n in windows},
        "public_exploit_at_snapshot": sum(1 for r in rows
                                          if r["public_exploit_at_snapshot"]),
        "cvss_high_or_above": sum(1 for r in rows if r["cvss_score"] >= 7.0),
        "epss_at_or_above_0.1": sum(1 for r in rows if r["epss_score"] >= 0.1),
        "median_epss": _median([r["epss_score"] for r in rows]),
        "kev_entrants_not_in_population": unreachable,
    }
    stats["positive_rate"] = {
        f"{n}d": round(stats["positives"][f"{n}d"] / len(eligible), 6) if eligible else 0.0
        for n in windows
    }
    return rows, stats


def _model_version(snapshot: date) -> str:
    """EPSS model version, or 'injected' when the scores did not come from the archive."""
    try:
        return sources.epss_model_version(snapshot)
    except Exception:
        return "injected"


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else round((s[mid - 1] + s[mid]) / 2, 5)


def write_snapshot(rows: list[dict], snapshot: date, out_dir: Path,
                   windows=DEFAULT_WINDOWS) -> Path:
    """Write one snapshot as a gzipped CSV — ~6 MB compressed per ~330k rows."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"historical_{snapshot.isoformat()}.csv.gz"
    fields = [f for f in FIELDS if not f.startswith("later_kev_")] + \
             [f"later_kev_{n}d" for n in windows]
    with gzip.open(path, "wt", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def build(snapshots=DEFAULT_SNAPSHOTS, windows=DEFAULT_WINDOWS,
          out_dir: Path = HISTORICAL_DIR) -> dict:
    """
    Build the full historical dataset and its manifest.

    The manifest records source hashes, EPSS model versions and the KEV catalog date, so
    a later rebuild can be compared against the inputs the paper actually used — which is
    what makes the numbers checkable when the raw sources cannot be redistributed.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    print("[*] Loading shared inputs (CVSS index, KEV catalog, Exploit-DB)...")
    cvss_index = nvd_cvss.load_index()
    kev_dates = sources.load_kev_dates()
    exploits = exploit_dates()
    print(f"[+] CVSS index: {len(cvss_index):,} CVEs | KEV: {len(kev_dates):,} | "
          f"Exploit-DB: {len(exploits):,} CVEs with dated exploits")

    per_snapshot, files = [], []
    for snapshot in snapshots:
        print(f"\n[*] Snapshot {snapshot.isoformat()}")
        rows, stats = build_snapshot(snapshot, windows, cvss_index=cvss_index,
                                     kev_dates=kev_dates, exploits=exploits)
        path = write_snapshot(rows, snapshot, out_dir, windows)
        stats["file"] = path.name
        stats["sha256"] = sources.sha256(path)
        stats["bytes"] = path.stat().st_size
        per_snapshot.append(stats)
        files.append(path)
        print(f"[+] {len(rows):,} rows -> {path.name} ({path.stat().st_size:,} bytes)")
        print(f"    eligible {stats['eligible']:,} | positives "
              + " ".join(f"{k}={v}" for k, v in stats["positives"].items()))

    manifest = {
        "dataset": "historical",
        "built": datetime.now().astimezone().isoformat(timespec="seconds"),
        "snapshots": [s.isoformat() for s in snapshots],
        "outcome_windows_days": list(windows),
        "sources": {
            "epss": {
                "url_template": sources.EPSS_DAILY_URL,
                "files": {s.isoformat(): {
                    "sha256": sources.sha256(sources.epss_snapshot_path(s)),
                    "model_version": sources.epss_model_version(s),
                } for s in snapshots},
            },
            "kev": {
                "url": sources.KEV_URL,
                "catalog_version": sources.kev_catalog_date(),
                "sha256": sources.sha256(sources.kev_path()),
                "note": "Single current download; dateAdded yields both snapshot state "
                        "and future outcome. The download date bounds how far forward "
                        "outcomes can be observed.",
            },
            "cvss": {
                "source": "NVD API 2.0",
                "sha256": sources.sha256(nvd_cvss.index_path()),
                "approximation": "Current base score used as a stand-in for the score at "
                                 "snapshot time; NVD publishes no per-date archive. Base "
                                 "scores are set at publication and revised rarely. CVEs "
                                 "published after a snapshot are excluded outright.",
            },
            "exploit_db": {
                "note": "date_published gives the earliest public exploit per CVE, so the "
                        "feature is evaluated as of each snapshot rather than as of today.",
            },
        },
        "label_policy": {
            "positive": "Entered CISA KEV strictly after the snapshot, within the window.",
            "unknown": "Did not enter KEV in the window. NOT asserted as un-exploited — "
                       "KEV is high-confidence positive evidence, not a census.",
            "excluded": "Already in KEV at the snapshot (eligible=False): exploitation was "
                        "an input to the decision, not a prediction target.",
        },
        "resampling_note": "The same CVE appears at multiple snapshots and those rows are "
                           "correlated. Bootstrap resampling must cluster by cve_id.",
        "per_snapshot": per_snapshot,
        "totals": {
            "rows": sum(s["rows"] for s in per_snapshot),
            "eligible": sum(s["eligible"] for s in per_snapshot),
            "positives": {f"{n}d": sum(s["positives"][f"{n}d"] for s in per_snapshot)
                          for n in windows},
            "kev_entrants_not_in_population": {
                f"{n}d": {
                    reason: sum(s["kev_entrants_not_in_population"][f"{n}d"][reason]
                                for s in per_snapshot)
                    for reason in ("published_after_snapshot", "absent_from_epss")
                } for n in windows
            },
        },
        "population_ceiling_note": (
            "A majority of KEV additions within each window concern CVEs published AFTER "
            "the snapshot. Those vulnerabilities did not exist when the prioritization "
            "decision was made, so no method operating on the population at T could have "
            "flagged them. They are excluded from the positive set rather than counted as "
            "missed detections, and the counts are reported per window so the bound on "
            "achievable recall is visible."),
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n[+] Manifest: {manifest_path}")
    return manifest


def load(snapshot: date, out_dir: Path = HISTORICAL_DIR) -> list[dict]:
    """Read one built snapshot back, with typed fields."""
    path = out_dir / f"historical_{snapshot.isoformat()}.csv.gz"
    if not path.exists():
        raise FileNotFoundError(f"{path} not built yet — run scripts/build_dataset.py")
    rows = []
    with gzip.open(path, "rt", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            for key in ("epss_score", "epss_percentile", "cvss_score"):
                row[key] = float(row[key] or 0.0)
            for key in list(row):
                if key.startswith("later_kev_") or key in (
                        "kev_at_snapshot", "eligible", "public_exploit_at_snapshot"):
                    row[key] = row[key] == "True"
            rows.append(row)
    return rows
