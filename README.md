# DevSecOps AI Pipeline with Kubernetes Security Scanning

> **CNIT/PNTLab Pisa · TECIP · Scuola Superiore Sant'Anna — AI Security Internship 2026**

---

## Research Problem

Automate security scanning of containerised microservices inside a CI/CD pipeline using AI-assisted vulnerability triage, integrating tools such as Trivy, Falco, and OPA Gatekeeper.

---

## Objectives

1. Conduct a systematic literature review on the topic.
2. Design and implement a proof-of-concept prototype.
3. Evaluate the prototype on real or benchmark datasets.
4. Document findings in a final technical report.
5. Present results to the research group.

---

## Expected Deliverables

| Deliverable | Due |
|---|---|
| Literature review (`docs/literature-review.md`) | Week 2 |
| Architecture design document (`docs/proposal.md`) | Week 3 |
| Working prototype (`src/`) | Week 6 |
| Evaluation results (`experiments/results/`) | Week 7 |
| Final report (`docs/final-report.md`) | Week 8 |

---

## Recommended Technology Stack

```
Python, FastAPI, PyYAML, Docker, Kubernetes, Trivy, GitHub Actions
```

See `requirements.txt` for pinned dependencies.

---

## Weekly Workflow

```
Monday     – Review weekly tasks in tasks/week-XX.md
Tue–Thu    – Implementation / experiments
Friday     – Document progress in docs/weekly-progress.md
Friday     – Open weekly Pull Request from your branch → dev
```

---

## Branching Policy

| Branch | Purpose |
|---|---|
| `main` | Stable, supervisor-reviewed code only |
| `dev` | Integration branch — merge weekly PRs here |
| `<your-name>-week-XX` | Your working branch for each week |

**Students must never push directly to `main`.**

---

## Pull Request Policy

- One PR per week, targeting the `dev` branch.
- PR title format: `[Week XX] Brief description`
- PR description must reference the weekly task file and summarise what was done.
- A supervisor or co-student must review before merging.

---

## Getting Started

```bash
# 1. Clone the repository
git clone https://github.com/AI-Security-Internships-2026/07-devsecops-ai-kubernetes.git
cd 07-devsecops-ai-kubernetes

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your weekly branch
git checkout dev
git pull origin dev
git checkout -b your-name-week-01

# 5. See available commands
python run.py --help
```

---

## Usage (CLI)

All functionality is exposed through a single entry point, `run.py`.

**Core triage pipeline:**

```bash
python run.py scan nginx:latest                                        # Stage 1: Trivy scan -> JSON
python run.py enrich experiments/results/trivy_nginx_latest.json       # Stage 2: add EPSS scores
python run.py triage experiments/results/epss_enriched_trivy_nginx_latest.json  # Stage 3: SSVC + LLM triage
python run.py pipeline nginx:latest                                    # Stages 1-3 in one command
```

**CVE-intelligence database + fresh-CVE watcher:**

```bash
python run.py db-setup                        # initialise the SQLite CVE-intelligence DB
python run.py sbom nginx:latest               # generate + store a CycloneDX SBOM
python run.py db-poll                         # pull the latest CVEs from NVD + OSV
python run.py watch                           # one fresh-CVE alert pass (SBOM x feeds)
python run.py watch --interval 3600           # continuous: repeat every hour (Ctrl-C to stop)
```

**Assistant, policy, and runtime signals:**

```bash
python run.py chat                                              # interactive CLI chatbot over the MCP tools
python run.py gatekeeper experiments/results/triage_run.json   # generate OPA Gatekeeper policy YAML
python run.py falco-capture falco_alerts.json                  # parse a Falco JSON alert stream
```

`triage` and `pipeline` also write a compact machine-readable
`experiments/results/triage_run.json` (image, CVE, CVSS, EPSS, KEV status, SSVC
decision, rationale, timestamp, errors).

Optional LLM explanations use **Groq** or **Google Gemini** — set
`GROQ_API_KEY` or `GOOGLE_API_KEY` in `.env` (see `.env.example`). The pipeline
works without a key (deterministic explanations).

The seven MCP servers (scanner, epss, ssvc, kev, cvedb, k8s-context, report) are
also exposed to Claude Code / Copilot through `.mcp.json`.

---

## Project Structure

```
run.py              # unified CLI entry point
.mcp.json           # MCP server config for Claude Code / Copilot
src/
  config.py         # repo-relative paths
  pipeline.py       # scan -> enrich -> triage orchestrator
  scanners/         # trivy_scanner.py
  enrichment/       # epss_client.py, kev_client.py, exploit_db.py
  context/          # k8s_context.py (cluster-optional deployment context)
  triage/           # ssvc.py (decisions), engine.py (analysis), explain.py (LLM),
                    # report.py (grouped reports), compact.py (triage_run.json),
                    # triage_agent.py (LangGraph)
  database/         # db.py + schema.sql, sbom.py, matcher.py, watcher_agent.py,
                    # pollers/ (nvd_poller.py, osv_poller.py)
  mcp_servers/      # seven FastMCP servers + common.py
  chatbot/          # cli.py (interactive assistant)
  enforce/          # gatekeeper.py (OPA Gatekeeper policy YAML)
  runtime/          # falco_client.py (Falco alert parsing)
experiments/results/  # scan outputs + committed triage_run.json
scripts/            # setup_database.sh, validate_phase*.sh
docs/               # weekly-progress.md, proposal.md, literature-review.md
```

---

## Roadmap to September 8, 2026

**Current state:** the core triage pipeline (Trivy → EPSS → CISA KEV → SSVC → report), the CVE-intelligence database (NVD/OSV pollers, SBOM ingestion, matcher, LangGraph watcher agent), Kubernetes deployment context, and the Exploit-DB signal are all merged through Week 6. Week 7 adds the seven MCP servers + interactive CLI chatbot, OPA Gatekeeper policy generation, and Falco runtime-alert capture; wiring Falco and Gatekeeper into the main pipeline is the Week 8 focus.

**Novel contribution target:** fuse SBOM component matching with *live* exploit-availability signals and Kubernetes runtime reachability — most SSVC-style triage tools score CVEs in the abstract; scoring by whether the vulnerable component is actually reachable/running in a live cluster is a genuinely current, under-addressed angle in DevSecOps triage.

| Date | Milestone |
|---|---|
| **Aug 2 (urgent)** | Open the PR for the 18 pending commits now; commit a fresh `experiments/results/triage_run.json` |
| Aug 9 | Fuse SBOM + live CVE feed + Exploit-DB signals into a single SSVC score |
| Aug 16 | Add Kubernetes-runtime-reachability weighting — is the vulnerable component actually live in the cluster? |
| Aug 23 | Benchmark the fused, reachability-aware score against CVSS-only and EPSS-only baselines on labeled incidents |
| Aug 30 | Full write-up |
| Sep 6 | Paper draft |
| **Sep 8** | **Final submission** |

---

## Supervisor Note

This repository is managed by **CNIT/PNTLab Pisa, TECIP, Scuola Superiore Sant'Anna**.
Please contact your supervisor before making architectural changes.
All code must be original or properly attributed.
Do **not** commit API keys, passwords, or large datasets — see `.gitignore`.
