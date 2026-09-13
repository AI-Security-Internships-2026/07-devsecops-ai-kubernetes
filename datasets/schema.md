# Dataset schema

Field-level definitions for the evaluation datasets (issue #21).

---

## Dataset A — `historical/historical_<snapshot>.csv.gz`

One row per `(cve_id, snapshot_date)`. Gzipped CSV with a header row.

The columns are grouped by their temporal role, and that grouping is the point: anything
in **Features** was knowable on the snapshot date, anything in **Labels** happened
strictly afterwards. Mixing the two is the leakage this dataset exists to prevent.

### Identity

| Field | Type | Description |
|---|---|---|
| `cve_id` | string | CVE identifier, uppercase (`CVE-2023-44487`) |
| `snapshot_date` | date | The feature freeze date T, `YYYY-MM-DD` |

### Features — as known at T

| Field | Type | Range | Source | Description |
|---|---|---|---|---|
| `epss_score` | float | 0.0–1.0 | EPSS daily archive for T | Probability of exploitation in the next 30 days, **as published on T** |
| `epss_percentile` | float | 0.0–1.0 | EPSS daily archive for T | Rank within that day's scored population |
| `cvss_score` | float | 0.0–10.0 | NVD | Base score. ⚠️ **Approximated** — current value, see below |
| `cvss_severity` | string | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`/`UNKNOWN` | NVD | Qualitative rating |
| `cvss_version` | string | `3.1`/`3.0`/`2.0`/`none` | NVD | Which CVSS generation produced the score; needed to interpret it |
| `published` | date | — | NVD | CVE publication date. Rows where this is after `snapshot_date` are excluded at build time |
| `public_exploit_at_snapshot` | bool | — | Exploit-DB `date_published` | An exploit was publicly available **on or before** T |
| `kev_at_snapshot` | bool | — | KEV `dateAdded` | Already in CISA KEV on T — an *input* to the decision, not a target |

### Labels — observed strictly after T

| Field | Type | Description |
|---|---|---|
| `later_kev_30d` | bool | Entered KEV in `(T, T+30]` |
| `later_kev_60d` | bool | Entered KEV in `(T, T+60]` |
| `later_kev_90d` | bool | Entered KEV in `(T, T+90]` |
| `kev_date_added` | date \| empty | KEV `dateAdded`, if ever added. Empty otherwise |
| `eligible` | bool | `False` when `kev_at_snapshot` is true. Ineligible rows are **not** prediction targets |

Windows are **nested, not exclusive**: a CVE added at T+45 is `False` at 30d and `True`
at both 60d and 90d. Window boundaries are inclusive at the horizon (T+30 counts as 30d).

---

## Semantics that are easy to get wrong

**`eligible=False` rows are kept, not dropped.** A CVE already in KEV at T had its
exploitation status handed to the method as an input. Counting a correct "Act" on it as a
successful prediction would credit the method for reading what it was given. The rows
remain so the manifest can report how many were excluded and why; every positive-rate
figure is computed over the eligible population only.

**A false label is not a negative.** `later_kev_90d == False` means *no confirmed
exploitation evidence appeared in that window*, not *this was not exploited*. KEV is a
curated catalog of confirmed exploitation, not a census. Any metric requiring a negative
class must state the operational proxy it adopts; this dataset does not supply one.

**Rows are correlated across snapshots.** The same `cve_id` appears at all three
snapshot dates with different feature values. These are repeated measures, not
independent observations — bootstrap resampling must cluster by `cve_id`.

**CVSS is the one approximated feature.** EPSS, KEV and exploit evidence are all genuinely
point-in-time; CVSS is not, because NVD publishes no per-date archive. The current base
score is used throughout. Base scores are assigned at publication and revised rarely, so
the approximation is reasonable — but it is recorded as an approximation in the manifest
and should be stated in the paper's threats-to-validity section rather than presented as
frozen truth.

---

## `historical/manifest.json`

Provenance and statistics for a build.

| Key | Description |
|---|---|
| `built` | Build timestamp |
| `snapshots`, `outcome_windows_days` | Build parameters |
| `sources.epss.files[<date>]` | SHA-256 and EPSS model version per snapshot file |
| `sources.kev` | Catalog version, SHA-256, and a note on how `dateAdded` yields both snapshot state and outcome |
| `sources.cvss` | SHA-256 of the NVD index and the explicit approximation statement |
| `sources.exploit_db` | How point-in-time exploit evidence is derived |
| `label_policy` | Positive / unknown / excluded definitions |
| `resampling_note` | The clustering requirement above |
| `per_snapshot[]` | Row counts, eligibility, positives per window, median EPSS, baseline population sizes |
| `totals.kev_entrants_not_in_population` | KEV entrants excluded because the CVE did not exist at T, split by reason |
| `population_ceiling_note` | Why those exclusions bound achievable recall for **any** method |

Hashes exist so a rebuild can be compared against the inputs the paper used, since the
bulk upstream sources are cached locally rather than redistributed.

---

## Dataset B — `kubernetes-controlled/`

Pending. Ground truth will be recorded directly from the controlled setup (deployed /
exposed / privileged state, the package intentionally executed, the Falco event
intentionally triggered) rather than derived from the prioritization rules under
evaluation, which would be circular.
