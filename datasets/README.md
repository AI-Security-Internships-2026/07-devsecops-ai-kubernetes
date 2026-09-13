# Datasets

> **Note on the policy below.** The repository policy is "do not commit raw datasets".
> The evaluation dataset described further down is an **explicit, documented exception**,
> because issue #26 requires every number in the paper to map to a committed artifact.
> The exception is narrow and the policy's three stated concerns do not apply to it:
>
> | Concern | This dataset |
> |---|---|
> | Large files slow down Git | 9.2 MB gzipped in total, three files |
> | May violate data licences | CVE identifiers and derived numeric fields only, from NVD (US Government public domain), FIRST EPSS and CISA KEV. The bulk upstream sources are **not** redistributed |
> | GDPR risks | No personal data of any kind |
>
> If the supervisor prefers the policy applied strictly, the data files can be dropped and
> rebuilt from `scripts/build_dataset.py`; `manifest.json` carries a SHA-256 per source so
> a rebuild is verifiable against the inputs the paper used. Removing them is one command:
> `git rm --cached datasets/historical/*.csv.gz` plus a `.gitignore` line.

## Policy

**Do NOT commit raw datasets to this repository.**
Large files slow down Git, may violate data licences, and create GDPR risks.

## How to document your dataset

For every dataset you use, create a file `datasets/<dataset-name>.md` with the following fields:

```markdown
## Dataset Name

- **Source URL:** https://...
- **Licence:** (e.g. CC BY 4.0, MIT, custom — always verify!)
- **Version / date downloaded:** YYYY-MM-DD
- **Size:** (approximate: rows, GB)
- **Format:** (CSV, PCAP, JSON, HDF5, …)
- **Download command / script:** (e.g. `wget https://...`)
- **Preprocessing steps:**
  1. Step one
  2. Step two
- **Train / Val / Test split:**
- **Notes:**
```

## Recommended storage options

| Option | When to use |
|---|---|
| Local disk only | Small experiments (< 500 MB) |
| University NAS / HPC scratch | Medium datasets shared within the lab |
| Hugging Face Datasets | Public NLP/ML datasets |
| Zenodo | Archived research datasets with DOI |
| DVC (Data Version Control) | Any dataset tracked alongside code |

## Example: CIC-IDS-2017

- **Source URL:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Licence:** Research use — see website
- **Format:** PCAP + CSV
- **Preprocessing:** Extract flow features with CICFlowMeter

---

# Evaluation datasets (issue #21)

Two datasets, built for the publication evaluation (issue #21). They answer different
questions and are deliberately kept separate rather than merged into one corpus.

| | Dataset A — historical | Dataset B — controlled Kubernetes |
|---|---|---|
| Question | Would a method have flagged vulnerabilities that later acquired exploitation evidence? | Does deployment context and runtime attribution change decisions correctly? |
| Scale | ~937k rows, 3 snapshots | small, factorial scenarios |
| Ground truth | CISA KEV additions after the snapshot | recorded directly from the controlled setup |
| Status | ✅ built | ⏳ not yet built |

---

## Dataset A — historical vulnerability benchmark

### What it is

For each of three snapshot dates, every CVE that existed and was scored by EPSS on that
date, with the signals as they stood then, plus whether the CVE subsequently entered
CISA KEV within 30, 60 or 90 days.

```
Time T:  freeze EPSS, CVSS, KEV membership, public exploit evidence
              ↓
T → T+N:  observe whether the CVE enters CISA KEV
```

### Build

```bash
python scripts/build_dataset.py --cvss-index    # ~20 min, resumable, run once
python scripts/build_dataset.py --historical    # ~2 min, rebuildable
```

A free `NVD_API_KEY` reduces the first stage to ~3 minutes. Sources are cached under
`data/cache/dataset/` and hashed into `historical/manifest.json`.

### Characteristics (Table D1)

| Snapshot | Rows | Eligible | Already KEV at T | +30d | +60d | +90d |
|---|---:|---:|---:|---:|---:|---:|
| 2025-09-01 | 291,870 | 290,464 | 1,406 | 8 | 30 | 31 |
| 2026-01-01 | 308,934 | 307,450 | 1,484 | 10 | 22 | 37 |
| 2026-06-01 | 336,946 | 335,338 | 1,608 | 8 | 14 | 24 |
| **Total** | **937,750** | **933,252** | — | **26** | **66** | **92** |

EPSS model version: **v2025.03.14** (all three snapshots). KEV catalog: **2026.09.11**.

### A ceiling on achievable recall

Of the KEV additions occurring within each window, **only ~45% concern CVEs that existed
at the snapshot date**:

| Window | Predictable | Total KEV entrants | Not yet published at T |
|---|---:|---:|---:|
| 30d | 26 | 56 | 29 |
| 60d | 66 | 140 | 73 |
| 90d | 92 | 207 | 114 |

The remainder were published *after* the snapshot, so no method prioritizing the
population at T could have flagged them. They are excluded from the positive set rather
than counted as missed detections.

This is a property of the problem, not of any method: **roughly half of near-term
exploitation events involve vulnerabilities that did not exist at the last triage.** It
bounds what periodic prioritization can achieve and is an argument for continuous
re-scanning. A naive evaluation using today's KEV against today's EPSS would have counted
all 207 and silently credited methods with predicting CVEs that did not yet exist.

### Class balance

Positives are rare — 92 of 933,252 eligible rows at 90 days (~0.01%). This is realistic
rather than a sampling artifact: confirmed-exploited vulnerabilities are a small fraction
of all published vulnerabilities. Two consequences:

- Accuracy is meaningless here. Report recall/coverage against the positive set and
  precision or efficiency against the flagged set.
- The 30-day window has only 26 positives and is **underpowered** for confidence
  intervals. The 90-day window is the primary horizon; 30d and 60d show the trend.

### Label policy

- **Positive** — entered CISA KEV strictly after the snapshot, within the window.
- **Unknown** — did not enter KEV in the window. **Not** asserted as un-exploited: KEV is
  high-confidence positive evidence, not a census of exploitation. Any metric requiring a
  negative class must state its operational proxy.
- **Excluded** (`eligible=False`) — already in KEV at the snapshot. Exploitation was an
  *input* to the decision, not something to predict.

### Known limitations

1. **CVSS is approximated.** NVD publishes no per-date archive, so the current base score
   stands in for the score at T. Base scores are assigned at publication and revised
   rarely, but this is an approximation, not point-in-time truth. CVEs published after a
   snapshot are excluded outright, which removes the one temporal error this would
   otherwise introduce.
2. **KEV is not a complete exploitation census.** It is a curated catalog of *confirmed*
   exploitation, so absence is not evidence of safety.
3. **Rows are correlated across snapshots.** The same CVE appears at all three dates.
   Bootstrap resampling must cluster by `cve_id`; treating rows as independent would
   produce misleadingly tight confidence intervals.
4. **EPSS model version is fixed at v2025.03.14** across snapshots, so scores are
   comparable between them — but figures are not directly comparable to published results
   computed under EPSS v1–v3.
5. **One CVE** was published before a snapshot yet missing from that day's EPSS file — a
   negligible coverage gap, recorded rather than silently dropped.

### Redistribution

The built dataset contains only CVE identifiers and derived numeric fields, all from
public sources. The upstream bulk sources are cached locally and **not** redistributed
here; `manifest.json` records a SHA-256 for each so a rebuild can be checked against the
inputs the paper used.

---

## Dataset B — controlled Kubernetes context & runtime benchmark

Not yet built. Will record ground truth directly from the controlled setup — whether an
image is deployed, exposed, privileged, which package was intentionally executed, and
which Falco event was intentionally triggered — rather than deriving it from the
prioritization rules under test, which would be circular.

---

## Files

```
datasets/
  README.md                         this file
  schema.md                         field-level definitions
  historical/
    manifest.json                   provenance, hashes, statistics  (committed)
    historical_<snapshot>.csv.gz    one file per snapshot           (committed)
  kubernetes-controlled/            Dataset B (pending)
```
