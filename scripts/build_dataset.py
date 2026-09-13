#!/usr/bin/env python3
"""
Build the publication evaluation dataset (issue #21).

Two stages, because the first is a slow one-time download and the second is fast and
re-runnable:

    python scripts/build_dataset.py --cvss-index     # ~20 min, resumable, once
    python scripts/build_dataset.py --historical     # ~2 min, rebuildable

Everything is cached under data/cache/dataset/ and hashed into the dataset manifest, so
a rebuild can be checked against the inputs the paper used even though the raw sources
are too large — and in NVD's case too licence-encumbered — to redistribute wholesale.

An NVD API key (free, from nvd.nist.gov) cuts the index build from ~20 minutes to ~3:

    export NVD_API_KEY=YOUR_NVD_API_KEY
"""

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.dataset import historical, nvd_cvss, sources   # noqa: E402


def parse_date(raw: str) -> date:
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not YYYY-MM-DD")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cvss-index", action="store_true",
                    help="build/resume the bulk NVD CVSS index (slow, run once)")
    ap.add_argument("--historical", action="store_true",
                    help="build Dataset A from the cached sources")
    ap.add_argument("--snapshots", nargs="+", type=parse_date,
                    default=list(historical.DEFAULT_SNAPSHOTS),
                    help="feature-freeze dates (default: %(default)s)")
    ap.add_argument("--windows", nargs="+", type=int,
                    default=list(historical.DEFAULT_WINDOWS),
                    help="outcome windows in days (default: %(default)s)")
    ap.add_argument("--out", type=Path, default=historical.HISTORICAL_DIR,
                    help="output directory")
    ap.add_argument("--refresh-kev", action="store_true",
                    help="re-download the KEV catalog (extends the observable horizon)")
    ap.add_argument("--rebuild-index", action="store_true",
                    help="discard and rebuild the CVSS index instead of resuming")
    args = ap.parse_args()

    if not (args.cvss_index or args.historical):
        ap.error("choose --cvss-index and/or --historical")

    if args.cvss_index:
        print("=" * 70)
        print("NVD CVSS index")
        print("=" * 70)
        nvd_cvss.build_index(resume=not args.rebuild_index)

    if args.historical:
        print("=" * 70)
        print("Dataset A — historical benchmark")
        print(f"snapshots: {', '.join(s.isoformat() for s in args.snapshots)}")
        print(f"windows:   {', '.join(str(w) + 'd' for w in args.windows)}")
        print("=" * 70)

        if args.refresh_kev:
            sources.fetch_kev_catalog(refresh=True)

        try:
            manifest = historical.build(tuple(args.snapshots), tuple(args.windows),
                                        args.out)
        except FileNotFoundError as e:
            print(f"[!] {e}")
            return 1

        print("\n" + "=" * 70)
        print("SUMMARY  (Table D1 source)")
        print("=" * 70)
        header = (f"{'snapshot':<13}{'rows':>10}{'eligible':>10}{'KEV@T':>8}"
                  + "".join(f"{'+' + str(w) + 'd':>7}" for w in args.windows))
        print(header)
        print("-" * len(header))
        for s in manifest["per_snapshot"]:
            print(f"{s['snapshot_date']:<13}{s['rows']:>10,}{s['eligible']:>10,}"
                  f"{s['kev_at_snapshot']:>8,}"
                  + "".join(f"{s['positives'][str(w) + 'd']:>7}" for w in args.windows))
        t = manifest["totals"]
        print("-" * len(header))
        print(f"{'TOTAL':<13}{t['rows']:>10,}{t['eligible']:>10,}{'':>8}"
              + "".join(f"{t['positives'][str(w) + 'd']:>7}" for w in args.windows))

        print(f"\n[+] Dataset: {args.out}")
        print(f"[+] Manifest: {args.out / 'manifest.json'}")
        print("[*] Reminder: rows for the same CVE across snapshots are correlated; "
              "resampling must cluster by cve_id.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
