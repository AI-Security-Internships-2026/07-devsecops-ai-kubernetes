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

_(Add a new section each week)_
