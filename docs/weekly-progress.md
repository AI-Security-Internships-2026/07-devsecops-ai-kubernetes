# Weekly Progress Log: DevSecOps AI Pipeline with Kubernetes Security Scanning

**Student:** Abdul Hadi
**GitHub username:** Unknown-086

---

## How to Use This File

Add a new section every Friday before opening your weekly Pull Request.
Be honest — problems and blockers are normal and help your supervisor support you.

---

## Week 1

**Branch:** `abdul-hadi-week-01`
**PR link:** https://github.com/AI-Security-Internships-2026/07-devsecops-ai-kubernetes/pull/1

### Completed this week
- [x] Read README and proposal
- [x] Set up local environment (Python venv, dependencies)
- [x] Ran `src/main.py` successfully
- [x] Wrote personal introduction (below)
- [x] Identified 5 related tools / frameworks / datasets

### Personal Introduction

I am Abdul Hadi, a final-year Software Engineering student from NUST. My expertise lies in web development, agentic AI, RAG systems, and DevOps. I have worked in a couple of organisations as a full-stack developer, which gave me hands-on experience with CI/CD pipelines, containerisation, and cloud-native tooling. Currently I am deepening my knowledge in agentic AI and DevSecOps — specifically how AI can be used to automate and prioritise security findings in modern software delivery pipelines.

### Problems / Blockers

No major blockers this week. Initial environment setup went smoothly. Spent time understanding the landscape of existing tools (Trivy, Snyk, Wiz) to inform the project direction.

### Next week plan
- Deep-dive into Trivy JSON output format and understand vulnerability data structure
- Begin drafting `docs/proposal.md` with system architecture
- Explore EPSS API integration for exploit probability scoring
- Set up a sample Kubernetes cluster (Minikube/Kind) for testing

---

## Week 2

**Branch:** `abdul-hadi-week-02`
**PR link:** https://github.com/AI-Security-Internships-2026/07-devsecops-ai-kubernetes/pull/2

### Completed this week
- [x] Added 2 academic papers to literature review (EPSS paper by Jacobs et al. 2023, AgenticVM by Arifin et al. 2026)
- [x] Drafted proposal sections 2–4 (Problem Statement, Research Questions, Methodology with full architecture)
- [x] Added PR link to Week 1 section
- [x] Implemented `src/trivy_scanner.py` — runs Trivy scan and captures JSON output
- [x] Implemented `src/epss_client.py` — fetches EPSS scores for CVEs from Trivy output
- [ ] Set up Minikube cluster (in progress)

### Problems / Blockers

Trivy requires Docker to be running for container image scanning. Local development uses `--input` mode with saved image tarballs as a workaround. EPSS API has no authentication but rate limiting may apply at scale — implemented local caching as mitigation.

### Next week plan
- Set up Minikube with Google Online Boutique (microservices-demo) as test target
- Implement SSVC decision engine that combines EPSS + K8s context
- Begin FastAPI server for the triage service
- Run first end-to-end scan → enrich → triage pipeline

---

## Week 3–4

**Branch:** `abdul-hadi-week-04`
**PR link:** https://github.com/AI-Security-Internships-2026/07-devsecops-ai-kubernetes/pull/4

### Completed this week
- [x] Implemented `src/triage_agent.py` — LangGraph triage agent (3-node StateGraph as per AgenticVM pattern)
- [x] Integrated CISA KEV catalog lookup (real-time fetch of known exploited vulnerabilities)
- [x] SSVC decision tree: CRITICAL/Act, HIGH/Attend, MEDIUM/Track*, LOW/Track
- [x] Per-CVE LLM-powered risk explanations and recommended actions (Groq/Llama-3.1 or Gemini)
- [x] Structured per-CVE output matching supervisor's expected format
- [x] Markdown + JSON triage report output
- [x] Added LangGraph, LangChain, langchain-groq, langchain-google-genai to `requirements.txt`
- [x] Created `.env.example` for API key configuration (Groq primary, Gemini fallback)
- [x] Created sample enriched data for testing (`experiments/results/epss_enriched_sample.json`)
- [x] Ran full end-to-end pipeline on VM: Trivy → EPSS → Triage Agent on `nginx:latest`
- [x] Achieved 93% alert reduction (272 CVEs → 19 actionable, 2 CRITICAL)

### Technical Details

The triage agent implements a 3-node LangGraph StateGraph:
1. **ingest_node** — reads EPSS-prioritized CVE JSON + fetches CISA KEV catalog
2. **analysis_node** — applies SSVC classification + LLM per-CVE risk explanation
3. **report_node** — outputs structured triage report (Markdown + JSON)

Per-CVE output format:
```json
{
  "cve": "CVE-2024-1234",
  "epss_score": 0.94,
  "priority": "CRITICAL",
  "explanation": "Plain-English risk explanation...",
  "recommended_action": "Patch within 24h or isolate container"
}
```

Decision thresholds (CISA SSVC):
- **CRITICAL / Act**: EPSS ≥ 0.1 OR in CISA KEV
- **HIGH / Attend**: EPSS ≥ 0.01 AND (CVSS ≥ 7.0 OR CRITICAL/HIGH severity)
- **MEDIUM / Track***: EPSS ≥ 0.01 (moderate risk, lower impact)
- **LOW / Track**: EPSS < 0.01 (safe to defer)

### Problems / Blockers

EPSS-only triage can over-prioritize old, well-known CVEs (e.g., CVE-2011-3389 BEAST attack — EPSS 0.73 due to automated scanning, but mitigated by TLS 1.2+ in practice). This validates the need for K8s deployment context to refine decisions. LLM explanations require an API key (Groq is free) but the agent works without one using static explanations.

### Next week plan
- Test pipeline against real-world K8s networking images (SR-IOV, Multus, Prometheus)
- Research DirtyClone (CVE-2026-43503) and test intentional vulnerability injection
- Add Kubernetes context enrichment (pod exposure, namespace)
- Begin FastAPI wrapper for the pipeline

---

## Week 5

**Branch:** `abdul-hadi-week-05`
**PR link:** https://github.com/AI-Security-Internships-2026/07-devsecops-ai-kubernetes/pull/6

### Completed this week (this PR)
- [x] Restructured the codebase into a proper Python package with a single CLI entry point (`run.py`)
- [x] Split the triage core into reusable modules: `triage/ssvc.py` (decisions), `triage/engine.py` (shared analysis loop), `triage/explain.py` (LLM/static), `triage/report.py` (grouped reports), `triage/compact.py` (machine-readable output)
- [x] **Fixed the duplicate-CVE bug** — findings are grouped by CVE ID with affected packages aggregated (multus scan: 883 per-package rows → 406 unique CVEs)
- [x] `src/pipeline.py` — one-command `scan → enrich → triage` orchestrator
- [x] Committed a **real end-to-end triage output** (`experiments/results/triage_run.json`) from a real Trivy scan

### End-to-End Result (committed)

Real Trivy scan of `ghcr.io/k8snetworkplumbingwg/multus-cni:v3.9.3`:

| Metric | Value |
|--------|-------|
| Unique CVEs analyzed | 406 |
| CRITICAL / Act | 17 |
| HIGH / Attend | 84 |
| MEDIUM / Track* | 54 |
| LOW / Track | 251 |
| Alert reduction | **75.1%** |

Top finding: CVE-2023-50387 (KeyTrap DNSSEC), EPSS 0.99995 → Act.

### Validation commands

Run from the repo root (see `README.md` for full usage):

```bash
# End-to-end run (Trivy -> EPSS -> CISA KEV -> SSVC/LangGraph triage)
python run.py pipeline ghcr.io/k8snetworkplumbingwg/multus-cni:v3.9.3
#   -> writes experiments/results/triage_run.json (the committed sample)

# Or stage by stage:
python run.py scan   <image>
python run.py enrich experiments/results/trivy_<image>.json
python run.py triage experiments/results/epss_enriched_trivy_<image>.json --image <image>
```

`triage_run.json` fields: container image, CVE ID, CVSS severity, EPSS score,
KEV status, SSVC decision, decision rationale, execution timestamp, and any
scanner/enrichment errors.

*(A test suite will be added in a later week; scripts are verified manually for now.)*

### Next week plan
- Submit the Kubernetes-context + CVE-intelligence-DB + MCP work in a follow-up PR
- Evaluation vs raw-CVSS baseline using CISA KEV as ground truth
- Add an automated test suite

---

## Week 6

**Branch:** `abdul-hadi-week-06`
**PR link:** https://github.com/AI-Security-Internships-2026/07-devsecops-ai-kubernetes/pull/8

### Completed this week
- [x] **Kubernetes deployment context** — `src/context/k8s_context.py` reads the
  cluster (pods, services, ingress, RBAC) to see if a scanned image is deployed,
  internet-facing, or privileged, and feeds that into the SSVC decision
  (cluster-optional — degrades gracefully with no cluster).
- [x] **Exploit-DB signal** — `src/enrichment/exploit_db.py` flags CVEs with a
  public exploit (SSVC "Automatable"), which escalates borderline findings.
- [x] **Own CVE-intelligence database** — SQLite schema + `db.py`, SBOM
  generation/storage, **NVD** + **OSV.dev** feed pollers, an SBOM×feed **matcher**,
  and a LangGraph **watcher agent** that raises fresh-CVE alerts. Linux
  `scripts/setup_database.sh` for setup.
- [x] **SSVC context bugfix** — fixed over-aggressive escalation that had inflated
  the alert count; context now adjusts a finding by at most one level and never
  inflates the actionable set.
- [x] Ran real end-to-end triage on two images and committed the machine-readable
  outputs to `experiments/results/`.

### End-to-End Results (committed)

| Image | Total CVEs | Act | Attend | Track* | Track | Alert reduction |
|-------|-----------:|----:|-------:|-------:|------:|----------------:|
| `ghcr.io/k8snetworkplumbingwg/multus-cni:v3.9.3` (old, internet-facing pod) | 417 | 22 | 83 | 55 | 257 | 74.8% |
| `nginx:latest` (current) | 167 | 0 | 0 | 0 | 167 | 100% |

- Files: `experiments/results/triage_run_multus-cni_v3.9.3.json`,
  `experiments/results/triage_run_nginx.json`.
- On the multus image, the **Kubernetes context escalated 5 exploitable HIGH
  findings to CRITICAL** because the pod was internet-facing (rationale recorded
  per finding, e.g. *"escalated HIGH->CRITICAL: internet-facing + EPSS 0.073"*).
- The contrast is the point: a **3-year-old image (multus)** has 22 urgent items,
  while a **current image (nginx:latest)** has **0** — all its CVEs are low
  exploit-probability. The tool cleanly separates the two.

### The context bug we fixed (short)

The first version of the K8s-context rule escalated *every* finding with EPSS ≥ 0.01
(exposed) **and** *every* finding unconditionally (privileged), and the two
**stacked** — so an exposed+privileged pod pushed criticals from 17 to **155**,
inflating the alert list. Fixed: context now moves a finding **at most one level**,
escalates only already-actionable HIGH→CRITICAL (EPSS ≥ 0.05, exposed/privileged),
never touches the MEDIUM/LOW noise, and de-escalates only borderline internal-only
criticals. Net: context **re-ranks urgency by deployment**, it does not flood the
queue (actionable set stays stable).

### Validation

- Live: NVD poller ingested hundreds of recent CVEs; OSV poller returned + parsed
  package vulns; the DB chain (SBOM → poll → match → classify) ran end-to-end; both
  pipeline runs above completed with `errors: []`.

### Problems / Blockers

The SBOM×feed matcher uses loose numeric version comparison, so fresh-CVE matches
are flagged `needs_verification` (distro backports don't always bump versions) —
positioned as early warning, with Trivy as the confirmatory scan. Automated test
suite still pending (manual verification for now).

### Next week plan (Week 7)
- **MCP servers + chatbot (full):** integrate and validate the seven MCP servers
  (scanner, epss, ssvc, kev, cvedb, k8s-context, report), wire the interactive CLI
  chatbot, and expose the same servers to Claude Code / Copilot via `.mcp.json` —
  so an analyst can ask "why is CVE-X urgent?" in natural language.
- **OPA Gatekeeper (policy generation):** generate Gatekeeper `ConstraintTemplate`
  + `Constraint` YAML from triage findings (e.g., block Act-level images, require
  pinned digests). YAML generation only this week; live admission enforcement is a
  follow-up.
- **Falco (runtime signal, lightweight):** install Falco in the Minikube cluster and
  capture/parse its runtime alert stream (JSON). Capture-only this week; wiring the
  runtime-observed signal into the SSVC decision is a follow-up.

---

## Week 7

**Branch:** `abdul-hadi-week-07`
**PR link:** https://github.com/AI-Security-Internships-2026/07-devsecops-ai-kubernetes/pull/11

### Completed this week
- [x] **Seven MCP servers** (`src/mcp_servers/`) — scanner, epss, ssvc, kev, cvedb,
  k8s-context, report — built on FastMCP (stdio), plus `.mcp.json` so Claude Code /
  Copilot can call the same tools an analyst would.
- [x] **Interactive CLI chatbot** (`run.py chat`, `src/chatbot/cli.py`) — a natural-
  language assistant that answers questions about scans by calling the MCP tools
  (Groq or Google Gemini backend), e.g. *"why would CVE-2023-45288 be critical?"*.
- [x] **OPA Gatekeeper policy generation** (`run.py gatekeeper`,
  `src/enforce/gatekeeper.py`) — emits `ConstraintTemplate` + `Constraint` YAML from a
  triage report (block Act-level images, require pinned digests, deny privileged).
  YAML generation only.
- [x] **Falco runtime-alert capture** (`run.py falco-capture`,
  `src/runtime/falco_client.py`) — parses a Falco JSON alert stream into normalised
  records and matches them to an image. Capture-only.
- [x] **Some fixes (from the Week 6):** the watcher now has a real
  continuous mode (`watch --interval N`) instead of one-shot only; removed dead code in `osv_poller.choose_cve_id`; corrected a
  stale `apply_context` docstring.
- [x] **Dependency fix (issue #9):** `run.py chat` failed because pip had
  installed `mcp 2.0.0` in the test environment, which removed `mcp.server.fastmcp` (our servers) and
  `mcp.shared.context.RequestContext` (needed by `langchain-mcp-adapters`). Capped
  `mcp>=1.9,<2.0` + `langchain-mcp-adapters>=0.3.0,<0.4`. Pure-Python version issue,
  not architecture-specific.
- [x] **Chat CLI hardening (found during test-environment runs):** (1) a failed Trivy
  scan called `sys.exit(1)` inside the scanner MCP server and crashed it, now raises
  `RuntimeError`, so the server survives and returns a tool error; (2) fixed the
  default Gemini model (retired preview → `gemini-2.5-flash`); (3) the assistant
  printed raw message content blocks (incl. Gemini's thought signature), now prints
  clean text; (4) the agent could loop over tool calls without answering, fixed with
  a decisive system prompt + a `recursion_limit` cap.

### Problems / Blockers
- **Falco and Gatekeeper are standalone commands, not yet wired into the main
  pipeline**. Full integration is the Week 8
  focus: Falco → SSVC reachability weighting, and Gatekeeper YAML as a pipeline output.
- **Chat CLI — resolved this week.** Three issues surfaced during test-environment
  runs and were fixed: the mcp 2.0 dependency mismatch (#9), the scanner MCP server
  crashing on a failed Trivy scan, and the agent looping over tool calls without
  answering.
- **Chat can't yet read saved reports by name** — the assistant answers from live CVE
  lookups but cannot discover/load a saved `triage_run*.json` by image or "latest", so
  it can't ground answers in a specific report.

### Next week plan (Week 8)
- **Integrate Falco into the pipeline** — fold the runtime signal into the SSVC
  decision as a *reachability* weighting (is the vulnerable component actually live in
  the cluster?).
- **Integrate Gatekeeper into the pipeline** — `pipeline --gatekeeper` auto-emits the
  policy YAML as a run artifact, so one command does scan → decide → enforce.
- **Kubernetes pod discovery** (`run.py discover`) — list running/stopped pods with
  image, namespace, status and exposure. (A `scan-cluster` command that triages every
  running image, plus automatic Falco-alert capture straight from the cluster, is
  designed now and scheduled for the following week.)
- **Watcher background service + status** — run the watcher in the background with a
  PID/status file; `watch --status` shows a live summary and re-running `watch` detects
  an already-running instance. Written OS-agnostically (with an optional systemd unit)
  so future multi-architecture / multi-OS support drops in cleanly.
- **Chat: read saved reports** — add MCP tools to discover/load a `triage_run*.json`
  by image or "latest", so the assistant can ground answers in a specific report.
---

## Week 8

**Branch:** `abdul-hadi-week-08`
**PR link:** _[Add link after opening PR]_

### Completed this week
- [x] **Falco → SSVC (runtime reachability)** — `ssvc.apply_runtime()` folds Falco
  runtime alerts into the decision, two-tier and image-level: a CRITICAL-tier Falco
  alert on an image escalates an already-actionable HIGH → CRITICAL (one level,
  never MEDIUM/LOW); lower-severity alerts only annotate the rationale. Threaded
  through the engine/agent and applied with
  `run.py pipeline <image> --falco <alerts.json>`.
- [x] **Gatekeeper → pipeline** — `run.py pipeline <image> --gatekeeper` runs
  scan→enrich→triage then emits the OPA Gatekeeper policy YAML from the result
  (scan → decide → generate-enforce in one command).
- [x] **`discover` command** — `k8s_context.discover_pods()` + `run.py discover`
  inventories every pod (running/non-running) with image, namespace, status,
  exposure and privilege; writes `cluster_inventory.json`. Cluster-optional.
- [x] **Background watcher + status** — the watcher writes a PID + status file, so
  `run.py watch --status` shows whether it's running with a summary, `--stop` stops
  it, and starting it twice is refused. Stdlib-only / OS-neutral; optional systemd
  unit in `scripts/cve-watcher.service`.
- [x] **Chat reads saved reports** — new `list_reports` / `get_report` MCP tools let
  the assistant answer about a saved triage report (by image or "latest") grounded
  in the stored SSVC decision/rationale, instead of guessing paths or re-scanning.
- [x] Update README with the new commands.

### Falco → SSVC design note
Falco maps alerts to a pod/container/image, not to a CVE, so this is an
*image-level* reachability signal,
applied to the findings in that image — not per-CVE exploitation proof. The two-tier
rule stays conservative (escalates only a borderline HIGH, and only on a
critical-tier alert), so it re-ranks urgency without inflating the actionable set —
consistent with the K8s-context escalation-capping fix.

### Problems / Blockers
- **Automatic Falco capture not in yet** — `--falco` still takes a captured file;
  pulling alerts straight from the running cluster (`--falco-live`) is designed and
  scheduled with `scan-cluster` feature.

### Next week plan (Week 9)
- **`scan-cluster`** — discover running images → triage each with K8s context +
  runtime reachability → one cluster-wide report; plus **automatic Falco capture**
  (`--falco-live`) straight from the cluster (no manual file).
- **Evaluation for the paper** — reachability-aware score vs CVSS-only / EPSS-only
  baselines (issue #10, TNSM target).
---

_(Add a new section each week)_
