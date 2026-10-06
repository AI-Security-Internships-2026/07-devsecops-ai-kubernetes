#!/usr/bin/env python3
"""
Generate the manuscript figures from committed run artifacts (#19, #26).

Every figure is drawn from a run directory, never from numbers typed by hand, so a
figure cannot disagree with the table beside it. Re-running an experiment and re-running
this script is the whole update path.

Print constraints drive the styling, and they differ from screen charts:

* **Grayscale legibility.** Reviewers print. Identity is carried by marker shape, line
  dash and direct labels; colour is a secondary cue that can be lost without the figure
  becoming unreadable.
* **Column width.** IEEE two-column text is ~3.4in wide, so single-column figures are
  sized to that and use 8pt type. Wide figures use `figure*` and 7.16in.
* **No interaction layer.** A static figure cannot defer anything to a tooltip, so
  anything the reader needs is labelled directly or stated in the caption.

The palette passes the six colour checks (lightness band, chroma floor, CVD separation,
normal-vision floor, contrast) against a white surface.
"""

import csv
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                      # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PUB = ROOT / "experiments" / "publication"
OUT = ROOT / "experiments" / "figures"

# Validated categorical slots, assigned in fixed order and never cycled.
BLUE, RUST, TEAL, VIOLET = "#3b5bdb", "#c2410c", "#0d9488", "#7c3aed"
INK, MUTED, GRID = "#1a1a1a", "#595959", "#d4d4d4"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["DejaVu Serif"],
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "text.color": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 400,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
})

COL, WIDE = 3.4, 7.16


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"{name}.{ext}")
    plt.close(fig)
    print(f"  [+] {name}.pdf / .png")


def read_csv(path):
    with open(path, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------- Fig: ladder

def fig_ladder(run="paper-ladder-90d"):
    """
    Progressive noise reduction.

    A waterfall is the right form: the quantity is one queue changing by stages, and the
    reader's question is how much each stage removed. Bars are drawn from the untriaged
    queue downward so the eye reads the reduction, and the one stage that *enlarges* the
    queue is coloured distinctly because a uniformly-subtractive reading would be wrong.
    """
    rows = read_csv(PUB / run / "tables" / "noise_ladder.csv")
    labels = [f"{r['rung']}  {r['label']}" for r in rows]
    vals = [int(r["actionable"]) for r in rows]
    # Growth is measured against the rung each row DECLARES as its comparison, not
    # against the row above it. L3 compares to L0, so reading it against L2 (the
    # adjacent row) would paint the single largest reduction in the figure as an
    # increase -- which an earlier version of this chart did.
    by_rung = {r["rung"]: int(r["actionable"]) for r in rows}

    fig, ax = plt.subplots(figsize=(COL, 2.6))
    for i, r in enumerate(rows):
        v = vals[i]
        cum = r["cumulative"] == "True"
        ref = by_rung.get(r["compare_to"])
        if r["rung"] == "L0":
            colour, hatch = MUTED, None          # the denominator, not a policy
        elif not cum:
            colour, hatch = MUTED, "///"         # single-signal alternative
        elif ref is not None and v > ref:
            colour, hatch = RUST, None           # this layer enlarges the queue
        else:
            colour, hatch = BLUE, None
        ax.barh(i, v, height=0.62, color=colour, hatch=hatch,
                edgecolor="white", linewidth=0.6)
        ax.text(v + max(vals) * 0.015, i, f"{v:,}", va="center", ha="left",
                fontsize=6.5, color=INK)

    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(labels, fontsize=6.5)
    ax.invert_yaxis()
    ax.set_xlabel("Findings in the actionable queue")
    ax.set_xlim(0, max(vals) * 1.22)
    ax.xaxis.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    ax.xaxis.set_major_formatter(lambda v, _: f"{int(v/1000)}k" if v else "0")

    handles = [plt.Rectangle((0, 0), 1, 1, color=MUTED, hatch="///", ec="white"),
               plt.Rectangle((0, 0), 1, 1, color=BLUE),
               plt.Rectangle((0, 0), 1, 1, color=RUST)]
    ax.legend(handles,
              ["single-signal policy", "cumulative layer", "layer enlarges the queue"],
              loc="lower right", frameon=False, handlelength=1.2)
    save(fig, "fig-ladder")


# ------------------------------------------------------ Fig: coverage/efficiency

def fig_tradeoff(run="paper-main-90d"):
    """
    Where each method sits on the coverage/efficiency plane.

    A scatter, not a bar chart: the claim is about a *trade-off between two quantities*,
    and separating them into two bar charts would hide exactly the relationship the
    reader needs. Recall carries a 95% CI because it rests on 92 positives; reduction's
    interval rests on 933k records and is too tight to draw, which the caption states
    rather than leaving the asymmetry unexplained.
    """
    rows = {r["method"]: r for r in read_csv(PUB / run / "summary_metrics.csv")}
    cis = json.loads((PUB / run / "confidence_intervals.json").read_text(encoding="utf-8"))

    # kev_epss is omitted as a separate point: it is numerically identical to epss_only
    # (zero discordant pairs), so plotting both would stack two markers and collide two
    # labels while implying they are distinguishable. The shared label states the
    # equivalence, which is the finding.
    order = ["cvss_only", "epss_only", "official_ssvc", "chaining", "kcavp"]
    nice = {"cvss_only": "CVSS-only", "epss_only": "EPSS-only\n$\\equiv$ KEV+EPSS",
            "official_ssvc": "Official SSVC", "chaining": "Chaining", "kcavp": "K-CAVP"}
    marks = {"cvss_only": "s", "epss_only": "o", "official_ssvc": "v",
             "chaining": "^", "kcavp": "*"}
    # Explicit offsets: Chaining and K-CAVP are within one CI of each other, so their
    # labels are pushed in opposite directions rather than auto-placed.
    offset = {"cvss_only": (0, 10), "epss_only": (34, -2), "official_ssvc": (-4, 10),
              "chaining": (26, 6), "kcavp": (-24, -4)}

    fig, ax = plt.subplots(figsize=(COL, 2.5))
    for m in order:
        r = rows.get(m)
        if not r:
            continue
        x, yv = float(r["workload_reduction"]) * 100, float(r["recall"]) * 100
        lo, hi = cis[m]["recall"]["lower"], cis[m]["recall"]["upper"]
        ours = m == "kcavp"
        colour = BLUE if ours else MUTED
        if lo is not None:
            ax.errorbar(x, yv, yerr=[[yv - lo * 100], [hi * 100 - yv]], fmt="none",
                        ecolor=colour, elinewidth=0.9, capsize=2, alpha=0.85)
        ax.scatter([x], [yv], marker=marks[m], s=80 if ours else 34,
                   color=colour, zorder=3, edgecolor="white", linewidth=0.6)
        ax.annotate(nice[m], (x, yv), textcoords="offset points",
                    xytext=offset[m], ha="center", fontsize=6.5,
                    color=INK if ours else MUTED,
                    fontweight="bold" if ours else "normal")

    ax.set_xlabel("Workload reduction (%)")
    ax.set_ylabel("Recall of confirmed\nexploited CVEs (%)")
    ax.set_xlim(44, 108)
    ax.set_ylim(-10, 108)
    ax.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    save(fig, "fig-tradeoff")


# ---------------------------------------------------------- Fig: threshold sweep

def fig_sweep(run="paper-sweep-90d"):
    """
    EPSS threshold sensitivity.

    Two measures on one x-axis with different units, which is the classic temptation to
    use a second y-axis. Both are percentages here, so one axis suffices; identity is
    carried by dash pattern and marker as well as colour, so the figure survives
    greyscale printing.
    """
    rows = sorted(read_csv(PUB / run / "tables" / "threshold_sweep.csv"),
                  key=lambda r: float(r["threshold"]))
    t = [float(r["threshold"]) for r in rows]
    red = [float(r["workload_reduction"]) * 100 for r in rows]
    rec = [float(r["recall"]) * 100 for r in rows]

    fig, ax = plt.subplots(figsize=(COL, 2.2))
    ax.plot(t, red, color=BLUE, lw=2, marker="o", ms=4, label="Workload reduction")
    ax.plot(t, rec, color=RUST, lw=2, ls="--", marker="^", ms=4, label="Recall")
    ax.axvline(0.10, color=MUTED, lw=0.9, ls=":")
    ax.annotate("operating point\n$\\tau_a = 0.10$", (0.10, 62),
                textcoords="offset points", xytext=(6, 0), fontsize=6.5, color=MUTED)
    ax.set_xlabel("EPSS threshold $\\tau_a$")
    ax.set_ylabel("Percent")
    ax.set_ylim(25, 100)
    ax.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="center left")
    save(fig, "fig-sweep")


# ------------------------------------------------------------- Fig: Dataset B

def fig_datasetb():
    """
    Dataset B outcomes against pre-registered expectations.

    The honest denominator is findings the ordinal ladder permitted to move, so the bar
    is moved/movable and the absolute counts are printed on each bar: a rate alone would
    hide that one scenario rests on 130 findings and another on 540.
    """
    data = json.loads((ROOT / "experiments" / "dataset-b" / "results.json")
                      .read_text(encoding="utf-8"))["results"]
    nice = {"exposed-nodeport": "Exposed (NodePort)",
            "exposed-loadbalancer": "Exposed (LB)",
            "privileged-internal": "Privileged, internal",
            "not-deployed": "Not deployed",
            "runtime-attributable": "Runtime, attributable",
            "runtime-unattributable": "Runtime, unattributable",
            "language-packages": "Language packages"}

    rows = [r for r in data if r["movable"]]
    fig, ax = plt.subplots(figsize=(COL, 2.4))
    for i, r in enumerate(rows):
        rate = 100.0 * r["moved_as_expected"] / r["movable"]
        colour = TEAL if rate >= 99 else (BLUE if rate > 0 else MUTED)
        ax.barh(i, rate, height=0.6, color=colour, edgecolor="white", linewidth=0.6)
        ax.text(rate + 2.5, i, f"{r['moved_as_expected']}/{r['movable']}",
                va="center", fontsize=6.5, color=INK)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([nice.get(r["scenario"], r["scenario"]) for r in rows],
                       fontsize=6.5)
    ax.invert_yaxis()
    ax.set_xlabel("Moved as pre-registered (% of movable)")
    ax.set_xlim(0, 136)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.xaxis.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    save(fig, "fig-datasetb")


def main():
    print("Generating manuscript figures from committed run artifacts")
    for fn in (fig_ladder, fig_tradeoff, fig_sweep, fig_datasetb):
        try:
            fn()
        except FileNotFoundError as e:
            print(f"  [!] {fn.__name__}: missing input {e.filename}")
        except Exception as e:                                   # pragma: no cover
            print(f"  [!] {fn.__name__}: {type(e).__name__}: {e}")
            return 1
    print(f"\n[+] {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
