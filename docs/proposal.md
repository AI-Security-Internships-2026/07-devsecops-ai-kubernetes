# Research Proposal: DevSecOps AI Pipeline with Kubernetes Security Scanning

**Student:** Abdul Hadi
**Supervisor:** CNIT/PNTLab Pisa
**Start date:** 2026-06-09
**Expected end date:** 2026-08-03

---

## 1. Background

Automate security scanning of containerised microservices inside a CI/CD pipeline using AI-assisted vulnerability triage, integrating tools such as Trivy, Falco, and OPA Gatekeeper.

This project is carried out within the AI Security research agenda of CNIT/PNTLab Pisa (TECIP, Scuola Superiore Sant'Anna).

Modern Kubernetes deployments typically contain hundreds of container images, each with dozens of dependencies. Running a vulnerability scanner like Trivy against a medium-sized cluster can easily produce 1,000+ CVE findings per scan. Security teams cannot manually review every finding, and naive CVSS-based sorting fails to predict real exploitation (AUPRC of only 0.051 per the EPSS study). Commercial solutions exist (Snyk at $7.4B valuation, Wiz at $32B acquisition) but are expensive and proprietary. There is a clear need for an open-source, AI-driven tool that intelligently triages container vulnerabilities using exploit probability, Kubernetes deployment context, and stakeholder-specific decision logic.

---

## 2. Problem Statement

Container vulnerability scanners (Trivy, Grype) generate overwhelming numbers of CVE findings without context-aware prioritisation. A typical scan of a microservice cluster produces hundreds to thousands of CVEs, most of which are either unexploitable in context, not reachable from the network, or have no known exploit in the wild. Security teams suffer from alert fatigue — they either ignore all findings (dangerous) or attempt to fix everything (impossible). The missing piece is an intelligent triage layer that considers exploit probability (EPSS), Kubernetes deployment context (RBAC permissions), and organisational priority (SSVC methodology) to reduce raw findings to a ranked, actionable remediation list.

---

## 3. Research Questions

1. **RQ1:** Can EPSS scores combined with Kubernetes deployment metadata (namespace, network policies, service exposure) significantly reduce false-priority vulnerabilities compared to CVSS-only sorting?
2. **RQ2:** What is the optimal architecture for an AI-assisted vulnerability triage pipeline that integrates into existing CI/CD workflows without adding significant build time overhead?
3. **RQ3:** How effective is the SSVC decision-tree methodology when automated with AI and applied to containerised workloads at scale?

---

## 4. Proposed Methodology

### 4.1 Data Collection / Dataset

| Source | Type | Licence | Usage |
|--------|------|---------|-------|
| NVD API (services.nvd.nist.gov) | 357k+ CVE records with CVSS scores | Public domain | Reference data for vulnerability metadata |
| EPSS API (first.org/epss) | Daily exploit probability scores | Open access | Primary exploitation likelihood feature |
| CISA KEV Catalog | Known exploited vulnerabilities | Public domain | Ground truth for "actively exploited" label |
| Trivy JSON output | Container scan results | Apache 2.0 (tool) | Raw input to our triage pipeline |
| Google Online Boutique (microservices-demo) | Kubernetes demo application | Apache 2.0 | Test target for scanning and evaluation |

### 4.2 Approach

**System Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                     CI/CD PIPELINE                          │
│                  (GitHub Actions)                           │
└──────────────────────────┬──────────────────────────────────┘
                           │ trigger on push/PR
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 1: SCAN                                              │
│  ┌─────────┐  ┌─────────┐  ┌───────────────┐                │
│  │  Trivy  │  │  Falco  │  │ OPA Gatekeeper│                │
│  │ (image) │  │(runtime)│  │  (policies)   │                │
│  └────┬────┘  └────┬────┘  └───────┬───────┘                │
│       │            │               │                        │
│       └────────────┼───────────────┘                        │
│                    │ JSON findings                          │
└────────────────────┼────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 2: ENRICH                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  EPSS API    │  │  CISA KEV    │  │  K8s Context     │   │
│  │  (exploit    │  │  (known      │  │  (namespace,     │   │
│  │  probability)│  │  exploited)  │  │  exposure, RBAC) │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │                 │                   │             │
│         └─────────────────┼───────────────────┘             │
│                           │ enriched findings               │
└───────────────────────────┼─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 3: TRIAGE (AI Layer)                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  SSVC Decision Engine                                 │  │
│  │  ─────────────────────                                │  │
│  │  Input:  EPSS score + KEV status + K8s exposure       │  │
│  │  Logic:  Automated SSVC decision tree                 │  │
│  │  Output: Track | Track* | Attend | Act                │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  LLM Summariser (optional)                            │  │
│  │  ─────────────────────────                            │  │
│  │  Generates human-readable explanation for each        │  │
│  │  "Act" finding: what it is, why it's urgent,          │  │
│  │  and how to fix it                                    │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE 4: REPORT & GATE                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐   │
│  │  SARIF out  │  │  Dashboard   │  │  Severity Gate    │   │
│  │  (GitHub    │  │  (web UI)    │  │  (fail build if   │   │ 
│  │  Security)  │  │              │  │  "Act" findings)  │   │
│  └─────────────┘  └──────────────┘  └───────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Core Triage Logic (SSVC-based):**

1. **Exploitation:** Is EPSS > 0.1 OR is CVE in CISA KEV? → Active exploitation likely
2. **Automatable:** Does CVE have public exploit (Metasploit, Nuclei template)? → Attack is automatable
3. **Technical Impact:** Is CVSS base score ≥ 9.0? → Total impact
4. **Mission Prevalence:** Is affected pod internet-facing (LoadBalancer/NodePort/Ingress)? → High mission prevalence

Decision output:
- **Act** → Immediate remediation required (block deployment)
- **Attend** → Remediate within sprint (warn in PR)
- **Track*** → Monitor, fix when convenient
- **Track** → Accept risk, no action needed

### 4.3 Evaluation Metrics

| Metric | What it measures | Target |
|--------|-----------------|--------|
| Alert reduction rate | % of raw findings filtered out vs. manual triage | ≥ 90% (benchmark: AgenticVM achieved 97.9%) |
| Precision@Act | Of findings labelled "Act", how many are truly critical? | ≥ 85% |
| Recall@Act | Of truly critical findings, how many are caught? | ≥ 95% (must not miss real threats) |
| Pipeline latency | Time added to CI/CD by triage stage | < 60 seconds per scan |
| EPSS correlation | Do our "Act" findings have higher EPSS than "Track" findings? | Statistically significant (p < 0.05) |

### 4.4 Tooling

| Category | Tool | Purpose |
|----------|------|---------|
| Scanning | Trivy | Container image vulnerability scanning |
| Runtime | Falco | Runtime anomaly detection in containers |
| Policy | OPA Gatekeeper | Kubernetes admission control policies |
| Backend | FastAPI + Python | Triage service API |
| Enrichment | EPSS API, NVD API | Exploit probability and CVE metadata |
| LLM | Claude API / Ollama (local) | Human-readable summaries and reasoning |
| Orchestration | Kubernetes (Minikube for dev) | Target deployment environment |
| CI/CD | GitHub Actions | Pipeline integration |
| Output | SARIF, JSON | Standard security findings format |

---

## 5. Expected Outcome

A working, open-source prototype of an AI-assisted vulnerability triage tool for Kubernetes CI/CD pipelines that:

1. Accepts Trivy scan JSON as input
2. Enriches findings with EPSS scores and Kubernetes context
3. Applies automated SSVC decision logic to classify each CVE as Track/Track*/Attend/Act
4. Outputs prioritised findings in SARIF format (compatible with GitHub Security tab)
5. Optionally generates LLM-powered remediation summaries
6. Demonstrates ≥90% alert reduction on a test microservice cluster
7. Adds <60 seconds to CI/CD pipeline execution time

The tool is designed as a product — self-hostable, open-source, and usable by any team running Kubernetes without requiring expensive commercial platforms.

---

## 6. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| EPSS API rate limits or downtime | Medium | Cache EPSS scores locally (update daily); fallback to CVSS-only mode |
| LLM API costs exceed budget | Medium | Use Ollama (local, free) for development; Claude/GPT only for production; implement cost cap |
| Scope too broad (all 3 tools + AI) | High | Phase approach: Week 2–3 Trivy + EPSS core, Week 4–5 K8s context + SSVC, Week 6 working prototype |
| Alert reduction target not met | Medium | Start with strict thresholds; tune iteratively using CISA KEV as ground truth |
| Kubernetes complexity for testing | Low | Use Minikube + Google Online Boutique (pre-built K8s demo app) |

---

## 7. Timeline

| Week | Deliverable | Key Activities |
|------|-------------|----------------|
| 1 | Orientation + Literature | Environment setup, 5 tool/framework reviews |
| 2 | Literature review complete | 2 academic papers, proposal draft, first scripts (Trivy scanner, EPSS client) |
| 3 | Architecture design finalised | Finalise proposal, SSVC decision engine, FastAPI scaffold |
| 4 | Core pipeline integration | End-to-end: Trivy → EPSS enrichment → SSVC triage → JSON output |
| 5 | K8s context + CI/CD | Add Kubernetes metadata (pod exposure, namespace), GitHub Actions integration |
| **6** | **Working prototype** | Full pipeline: scan → enrich → triage → SARIF report. Demo-ready. |
| 7 | Evaluation results | Benchmark on Online Boutique, measure alert reduction, precision/recall |
| 8 | Final report | Write final report |

---

_Last updated: 2026-06-21_
