"""
Evaluation metrics, confidence intervals and paired significance tests (issue #22).

Dependency-free on purpose (stdlib + `math` only, no scipy). The evaluation has to be
reproducible from committed inputs years from now, and every dependency is one more thing
that can shift a published number between versions.

Two properties of this task shape every definition below.

**Precision is a lower bound, not a precision.** The dataset labels a finding positive
only when it entered CISA KEV after the snapshot; everything else is *unknown*, not
confirmed-safe. So a flagged finding that never appeared in KEV may have been exploited
without anyone recording it. Precision computed against known positives is therefore a
floor — and with ~92 positives in ~933k rows it is inherently tiny (~0.01%). That is a
property of vulnerability data, not a failure of a method, and the EPSS literature reports
the same quantity under the name *efficiency*. Both names are emitted so the numbers are
comparable to published work.

**Rows are correlated.** The same CVE appears at three snapshots. Bootstrap resampling
therefore draws whole CVEs, never individual rows — otherwise the same CVE lands in a
resample several times as if it were independent evidence, and the confidence intervals
come out far too narrow.
"""

import math
import random
from collections import defaultdict


# --------------------------------------------------------------- classification

def confusion(flagged: set, positives: set, population: set) -> dict:
    """
    Counts against a positives-and-unknowns label scheme.

    `fp` is named honestly: these are flagged items with no confirmed exploitation
    evidence, which is not the same as a wrong answer. `tn` is likewise "not flagged, not
    known positive" and carries no claim of safety.
    """
    tp = len(flagged & positives)
    fp = len(flagged - positives)
    fn = len(positives - flagged)
    tn = len(population - flagged - positives)
    return {"tp": tp, "fp_unconfirmed": fp, "fn": fn, "tn_unconfirmed": tn}


def classification_metrics(flagged: set, positives: set, population: set) -> dict:
    """
    Recall, precision (lower bound), F1, workload reduction.

    Recall is the trustworthy one: the positive set is curated and complete for what it
    claims, so "of the CVEs confirmed exploited in the window, how many did we flag?" has
    a real answer. Everything keyed on the flagged set inherits the unknown-label caveat.
    """
    c = confusion(flagged, positives, population)
    n_pop = len(population) or 1
    n_flagged = len(flagged)
    n_pos = len(positives)

    recall = c["tp"] / n_pos if n_pos else None
    precision = c["tp"] / n_flagged if n_flagged else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and (precision + recall) > 0 else 0.0)

    return {
        **c,
        "population": n_pop,
        "positives": n_pos,
        "actionable": n_flagged,
        "recall": recall,                       # == "coverage" in the EPSS literature
        "coverage": recall,
        "precision_lower_bound": precision,     # == "efficiency"
        "efficiency": precision,
        "f1_lower_bound": f1,
        "workload_reduction": 1 - (n_flagged / n_pop),
        "flagged_fraction": n_flagged / n_pop,
    }


# ---------------------------------------------------------------------- ranking

def precision_at_k(ranked_ids: list, positives: set, k: int) -> float:
    """Share of the top K that are confirmed positives."""
    if k <= 0:
        return 0.0
    top = ranked_ids[:k]
    return sum(1 for i in top if i in positives) / len(top) if top else 0.0


def recall_at_k(ranked_ids: list, positives: set, k: int) -> float:
    """Share of all confirmed positives captured in the top K."""
    if not positives:
        return 0.0
    return sum(1 for i in ranked_ids[:k] if i in positives) / len(positives)


def ndcg_at_k(ranked_ids: list, positives: set, k: int) -> float:
    """
    Binary-relevance NDCG@K.

    Included because #22 asks for it, but with a caveat worth carrying into the paper:
    with binary relevance and very few positives, NDCG adds little beyond Recall@K — its
    value is graded relevance, which this ground truth does not have.
    """
    if not positives or k <= 0:
        return 0.0
    dcg = sum(1 / math.log2(rank + 1)
              for rank, cve in enumerate(ranked_ids[:k], start=1) if cve in positives)
    ideal_hits = min(len(positives), k)
    idcg = sum(1 / math.log2(r + 1) for r in range(1, ideal_hits + 1))
    return dcg / idcg if idcg else 0.0


def ranking_metrics(ranked_ids: list, positives: set, ks=(10, 20, 50, 100)) -> dict:
    out = {}
    for k in ks:
        out[f"precision_at_{k}"] = precision_at_k(ranked_ids, positives, k)
        out[f"recall_at_{k}"] = recall_at_k(ranked_ids, positives, k)
        out[f"ndcg_at_{k}"] = ndcg_at_k(ranked_ids, positives, k)
    return out


# ------------------------------------------------------- bootstrap (clustered)

def clustered_bootstrap_ci(items: list, statistic, cluster_key, n_resamples: int = 1000,
                           alpha: float = 0.05, seed: int = 20260916) -> dict:
    """
    Percentile bootstrap CI, resampling whole clusters.

    `items` are the unit rows, `cluster_key(item)` returns the id that groups correlated
    rows (here: the CVE), and `statistic(sample)` computes the metric on a resample.

    Clusters are drawn with replacement and all of a cluster's rows come along together.
    Resampling rows independently would treat three snapshots of one CVE as three
    independent observations and shrink the interval accordingly — the specific error the
    dataset manifest warns about.

    Seeded, because a confidence interval that moves between runs of the same analysis is
    not reportable.
    """
    if not items:
        return {"point": None, "lower": None, "upper": None, "n_resamples": 0,
                "n_clusters": 0, "resampling_unit": "cluster"}

    by_cluster = defaultdict(list)
    for item in items:
        by_cluster[cluster_key(item)].append(item)
    clusters = list(by_cluster.values())

    point = statistic(items)
    rng = random.Random(seed)
    draws = []
    for _ in range(n_resamples):
        sample = []
        for _ in range(len(clusters)):
            sample.extend(rng.choice(clusters))
        value = statistic(sample)
        if value is not None:
            draws.append(value)

    if not draws:
        return {"point": point, "lower": None, "upper": None,
                "n_resamples": 0, "n_clusters": len(clusters),
                "resampling_unit": "cluster"}

    draws.sort()
    lo = draws[max(0, int((alpha / 2) * len(draws)) - 1)]
    hi = draws[min(len(draws) - 1, int((1 - alpha / 2) * len(draws)))]
    return {
        "point": point,
        "lower": lo,
        "upper": hi,
        "confidence": 1 - alpha,
        "n_resamples": len(draws),
        "n_clusters": len(clusters),
        "resampling_unit": "cluster (cve_id)",
    }


def bootstrap_proportion_ci(flags: list[bool], n_resamples: int = 2000,
                            alpha: float = 0.05, seed: int = 20260916) -> dict:
    """
    Percentile CI for a proportion, where each element is already one cluster.

    Collapsing to one boolean per CVE *before* resampling is what makes this a clustered
    bootstrap: every draw takes a whole CVE, so correlated snapshot rows can never be
    counted as independent observations. Once collapsed, the statistic is just a mean, so
    resampling is a vectorised operation rather than a pass over ~900k rows per draw —
    the difference between seconds and hours at this dataset's size.

    Falls back to pure Python without numpy so the evaluator keeps working from a bare
    stdlib install.
    """
    n = len(flags)
    if n == 0:
        return {"point": None, "lower": None, "upper": None, "n_clusters": 0,
                "n_resamples": 0, "resampling_unit": "cluster (cve_id)"}

    point = sum(flags) / n
    try:
        import numpy as np
        rng = np.random.default_rng(seed)
        arr = np.asarray(flags, dtype=np.int8)
        draws = rng.choice(arr, size=(n_resamples, n), replace=True).mean(axis=1)
        lo, hi = (float(x) for x in np.quantile(draws, [alpha / 2, 1 - alpha / 2]))
    except ImportError:
        rng = random.Random(seed)
        draws = sorted(sum(rng.choices(flags, k=n)) / n for _ in range(n_resamples))
        lo = draws[max(0, int((alpha / 2) * len(draws)) - 1)]
        hi = draws[min(len(draws) - 1, int((1 - alpha / 2) * len(draws)))]

    return {"point": point, "lower": lo, "upper": hi, "confidence": 1 - alpha,
            "n_clusters": n, "n_resamples": n_resamples,
            "resampling_unit": "cluster (cve_id)"}


# Resamples per chunk. Bounds peak memory in the vectorised bootstrap; the draws are
# identical to an unchunked run because each chunk draws from the same generator.
_BOOTSTRAP_CHUNK = 50


def clustered_proportion_ci(units: list[tuple], n_resamples: int = 2000,
                            alpha: float = 0.05, seed: int = 20260916) -> dict:
    """
    CI for a proportion when several units belong to one cluster.

    `units` is a list of (cluster_id, flag). The evaluation unit is (CVE, snapshot) but
    the *independent* unit is the CVE, so resampling draws CVEs and brings all of that
    CVE's snapshot rows with it. Resampling units directly would treat three snapshots of
    one CVE as three independent observations.

    Vectorised by pre-aggregating each cluster to (n_units, n_flagged), so a resample is
    two array sums rather than a pass over ~900k rows.
    """
    if not units:
        return {"point": None, "lower": None, "upper": None, "n_units": 0,
                "n_clusters": 0, "n_resamples": 0,
                "resampling_unit": "cluster (cve_id)"}

    totals, flags = defaultdict(int), defaultdict(int)
    for cluster, flag in units:
        totals[cluster] += 1
        flags[cluster] += 1 if flag else 0
    keys = list(totals)
    n_total = sum(totals.values())
    point = sum(flags.values()) / n_total

    try:
        import numpy as np
        t = np.fromiter((totals[k] for k in keys), dtype=np.int64, count=len(keys))
        f = np.fromiter((flags[k] for k in keys), dtype=np.int64, count=len(keys))
        rng = np.random.default_rng(seed)
        # Resample in chunks. A single (n_resamples x n_clusters) index array is
        # n_resamples * n_clusters * 8 bytes — at 2000 x 335k that is 5 GiB and the
        # allocation fails outright. Chunking caps peak memory at roughly
        # CHUNK * n_clusters * 8 * 3 while producing identical draws.
        chunk = max(1, min(n_resamples, _BOOTSTRAP_CHUNK))
        parts = []
        remaining = n_resamples
        while remaining > 0:
            size = min(chunk, remaining)
            idx = rng.integers(0, len(keys), size=(size, len(keys)))
            parts.append(f[idx].sum(axis=1) / t[idx].sum(axis=1))
            remaining -= size
        draws = np.concatenate(parts)
        lo, hi = (float(x) for x in np.quantile(draws, [alpha / 2, 1 - alpha / 2]))
    except ImportError:
        rng = random.Random(seed)
        draws = []
        for _ in range(n_resamples):
            picked = rng.choices(keys, k=len(keys))
            num = sum(flags[k] for k in picked)
            den = sum(totals[k] for k in picked)
            draws.append(num / den if den else 0.0)
        draws.sort()
        lo = draws[max(0, int((alpha / 2) * len(draws)) - 1)]
        hi = draws[min(len(draws) - 1, int((1 - alpha / 2) * len(draws)))]

    return {"point": point, "lower": lo, "upper": hi, "confidence": 1 - alpha,
            "n_units": n_total, "n_clusters": len(keys), "n_resamples": n_resamples,
            "resampling_unit": "cluster (cve_id)"}


# ------------------------------------------------------ paired significance

def _binom_two_sided_p(b: int, c: int) -> float:
    """Exact two-sided binomial p for McNemar, under H0: p = 0.5 on discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def mcnemar(a_correct: set, b_correct: set, items: set,
            exact_threshold: int = 25) -> dict:
    """
    McNemar's test on paired binary outcomes for two methods over the same items.

    Only discordant pairs carry information: items both methods got right, or both got
    wrong, say nothing about which is better. `b` counts items only method A got right and
    `c` only method B.

    The exact binomial test is used when discordant pairs are few, which they will be here
    given ~92 positives — the chi-square approximation is unreliable at those counts and
    would overstate significance.
    """
    b = len((a_correct & items) - b_correct)
    c = len((b_correct & items) - a_correct)
    n_disc = b + c

    if n_disc == 0:
        return {"b": 0, "c": 0, "discordant": 0, "statistic": None, "p_value": 1.0,
                "method": "none (no discordant pairs)", "significant_at_0.05": False}

    if n_disc < exact_threshold:
        p = _binom_two_sided_p(b, c)
        stat, kind = None, "exact binomial"
    else:
        # Continuity-corrected chi-square, 1 df; p via the erfc survival function so no
        # scipy dependency is needed.
        stat = (abs(b - c) - 1) ** 2 / n_disc
        p = math.erfc(math.sqrt(stat / 2))
        kind = "chi-square (continuity corrected)"

    return {"b": b, "c": c, "discordant": n_disc, "statistic": stat,
            "p_value": p, "method": kind, "significant_at_0.05": p < 0.05}


def paired_bootstrap_diff(items: list, stat_a, stat_b, cluster_key,
                          n_resamples: int = 1000, alpha: float = 0.05,
                          seed: int = 20260916) -> dict:
    """
    CI on the difference between two methods, resampled on the same clusters.

    Pairing matters: both methods are evaluated on each resample, so the difference is
    computed within-sample and the shared variation cancels. Bootstrapping each method
    separately and subtracting would inflate the interval and hide real differences.

    Use for ranking and top-K metrics, where McNemar does not apply.
    """
    if not items:
        return {"difference": None, "lower": None, "upper": None, "n_resamples": 0}

    by_cluster = defaultdict(list)
    for item in items:
        by_cluster[cluster_key(item)].append(item)
    clusters = list(by_cluster.values())

    point = stat_a(items) - stat_b(items)
    rng = random.Random(seed)
    diffs = []
    for _ in range(n_resamples):
        sample = []
        for _ in range(len(clusters)):
            sample.extend(rng.choice(clusters))
        diffs.append(stat_a(sample) - stat_b(sample))

    diffs.sort()
    lo = diffs[max(0, int((alpha / 2) * len(diffs)) - 1)]
    hi = diffs[min(len(diffs) - 1, int((1 - alpha / 2) * len(diffs)))]
    return {
        "difference": point,
        "lower": lo,
        "upper": hi,
        "confidence": 1 - alpha,
        "n_resamples": len(diffs),
        "resampling_unit": "cluster (cve_id)",
        # The interval excluding zero is the reportable claim; a p-value alone without
        # the effect size is what issue #26 explicitly rules out.
        "excludes_zero": (lo > 0) or (hi < 0),
    }


# ------------------------------------------------- runtime attribution (#25)

def attribution_metrics(cases: list[dict]) -> dict:
    """
    Attribution accuracy over labelled alert/package cases.

    Each case: {"expected_package": str|None, "attributed_package": str|None}.
    `expected_package` None means the evidence should NOT have been attributed to
    anything — the conservative case, and the one that matters most: a false attribution
    escalates a finding on evidence that has nothing to do with it.
    """
    tp = fp = fn = tn = unattributed = 0
    for case in cases:
        expected = case.get("expected_package")
        actual = case.get("attributed_package")
        if actual is None:
            unattributed += 1
            if expected is None:
                tn += 1          # correctly declined to attribute
            else:
                fn += 1          # missed a real link
        elif expected is None:
            fp += 1              # attributed evidence that should not have been
        elif actual == expected:
            tp += 1
        else:
            fp += 1              # attributed to the wrong package
            fn += 1              # and missed the right one

    n = len(cases) or 1
    attributed = tp + fp
    return {
        "cases": len(cases),
        "true_attributions": tp,
        "false_attributions": fp,
        "missed_attributions": fn,
        "correct_declines": tn,
        "attribution_precision": tp / attributed if attributed else None,
        "attribution_recall": tp / (tp + fn) if (tp + fn) else None,
        "false_attribution_rate": fp / n,
        "unattributed_rate": unattributed / n,
    }
