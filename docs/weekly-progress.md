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
**PR link:** _[Add link after opening PR]_

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
**PR link:** _[Add link after opening PR]_

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

_(Add a new section each week)_
