# Literature Review: DevSecOps AI Pipeline with Kubernetes Security Scanning

**Student:** Abdul Hadi
**Updated:** 2026-06-14

---

## Instructions

For each paper or resource you read, complete one entry below.
Aim for at least **10 papers** by the end of Week 2.
Use Google Scholar, IEEE Xplore, ACM DL, arXiv, or USENIX Security.

---

## Entry 1 — Trivy (Container Vulnerability Scanner)

| Field | Content |
|---|---|
| **Full title** | Trivy: Comprehensive Security Scanner for Containers and Cloud-Native |
| **Authors / Creator** | Aqua Security |
| **Year** | 2019–present (actively maintained) |
| **Venue** | Open-source tool (Apache 2.0 license) |
| **URL / DOI** | https://github.com/aquasecurity/trivy |
| **Method** | Scans container images, filesystems, Git repos, and Kubernetes clusters for OS package and language library vulnerabilities using CVE databases (NVD, Red Hat, Alpine, etc.). Outputs results in JSON, SARIF, and table formats. |
| **Dataset** | NVD, vendor advisory databases (Red Hat, Debian, Alpine, Ubuntu), GitHub Security Advisories |
| **Key result** | 36.4k+ GitHub stars; default scanner in GitLab Container Scanning, Harbor registry, and Artifact Hub. Low false-positive rate compared to alternatives. Supports SBOM generation. |
| **Limitation** | Produces raw vulnerability lists without intelligent prioritisation. All CVEs are treated equally — no context-aware triage (e.g., is the vulnerability reachable? is the service internet-facing?). No built-in AI/ML layer for filtering noise. |
| **Relevance to our project** | Trivy is our primary scanning engine. Our AI triage layer will consume Trivy's JSON output and add intelligent prioritisation on top — turning a noisy list of hundreds of CVEs into actionable, ranked remediation guidance. |

**Notes / Quotes:**
> Trivy is the most widely adopted open-source container scanner. Our project's value-add is not replacing Trivy but augmenting it with AI-driven context and prioritisation that it currently lacks.

---

## Entry 2 — Snyk Container (AI-Powered Vulnerability Scanning)

| Field | Content |
|---|---|
| **Full title** | Snyk Container: Developer-First Container Security with AI Prioritisation |
| **Authors / Creator** | Snyk Ltd. |
| **Year** | 2018–present |
| **Venue** | Commercial SaaS platform |
| **URL / DOI** | https://snyk.io/product/container-security/ |
| **Method** | Scans container images for OS and library vulnerabilities. Uses proprietary AI-driven risk prioritisation that considers exploitability, reachability analysis, and fix availability to rank findings. Integrates directly into CI/CD (GitHub, GitLab, Azure). Provides automated fix PRs. |
| **Dataset** | Snyk Vulnerability Database (proprietary), NVD, vendor advisories |
| **Key result** | Valued at $7.4B (2022). Used by enterprises globally. Key differentiator is "developer-first" UX — shows only actionable vulnerabilities with fix suggestions, reducing developer friction. AI prioritisation reduces noise significantly compared to raw CVE lists. |
| **Limitation** | Commercial and expensive ($100k+/year for enterprise). Proprietary AI — no transparency into how prioritisation decisions are made. Lock-in to Snyk ecosystem. Not self-hostable. |
| **Relevance to our project** | Snyk is our primary commercial competitor. Their AI prioritisation is what we aim to replicate in an open, transparent, and self-hostable manner. We can study their UX patterns (fix suggestions, severity filtering, reachability analysis) as a reference for our own product design. |

**Notes / Quotes:**
> Snyk's success proves the market demand for AI-powered vulnerability triage. The gap we fill: open-source, transparent, and self-hosted — for teams who cannot send vulnerability data to external SaaS platforms.

---

## Entry 3 — Wiz (Cloud Security Platform with AI Agents)

| Field | Content |
|---|---|
| **Full title** | Wiz: AI-Powered Cloud and Application Security Platform |
| **Authors / Creator** | Wiz Inc. (acquired by Google, 2025) |
| **Year** | 2020–present |
| **Venue** | Commercial cloud security platform |
| **URL / DOI** | https://www.wiz.io/ |
| **Method** | Agentless cloud security with three AI agents: Green Agent (auto-remediation), Red Agent (automated penetration testing), Blue Agent (threat hunting). Connects code security, cloud infrastructure, and runtime defence. Uses attack path analysis to identify toxic risk combinations. |
| **Dataset** | Scans live cloud environments (AWS, Azure, GCP) — no agents needed on VMs/containers |
| **Key result** | Acquired for $32B by Google (2025). Serves 50%+ of Fortune 100. Key innovation is "attack path analysis" — correlating multiple low-severity findings into a critical risk chain. |
| **Limitation** | Extremely expensive (enterprise-only pricing). Cloud-only — requires full cloud API access. Agentless approach means less deep runtime visibility than tools like Falco. Not applicable to on-premise or air-gapped environments. |
| **Relevance to our project** | Wiz represents the gold standard for AI-assisted security. Their attack path analysis concept (combining multiple findings into risk chains) is something we can adapt for our Kubernetes pipeline: a medium-severity CVE in an internet-facing pod with no network policy is more critical than a high-severity CVE in an isolated internal service. |

**Notes / Quotes:**
> Wiz's core insight: individual vulnerabilities are less important than their context. A critical CVE in an unreachable container is less urgent than a medium CVE in a public-facing pod with excessive permissions. Our AI triage should incorporate similar contextual reasoning.

---

## Entry 4 — EPSS (Exploit Prediction Scoring System)

| Field | Content |
|---|---|
| **Full title** | Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights |
| **Authors / Creator** | Jay Jacobs, Sasha Romanosky, Octavian Suciu, Benjamin Edwards, Armin Sarabi (FIRST.org SIG) |
| **Year** | 2023 (model continuously updated daily) |
| **Venue** | FIRST.org framework — free and open access |
| **URL / DOI** | https://www.first.org/epss/ |
| **Method** | Machine learning model that predicts the probability (0–1 scale) that a CVE will be exploited in the wild within the next 30 days. Uses features from NVD metadata, exploit databases, social media mentions, and dark web intelligence. Updated daily for every CVE. |
| **Dataset** | NVD (200k+ CVEs), exploit databases (Exploit-DB, Metasploit), threat intelligence feeds, historical exploitation data |
| **Key result** | 82% performance improvement over previous models in distinguishing exploited vs. non-exploited vulnerabilities. Adopted by Cisco, Qualys, and multiple enterprise tools. Free API access for all CVEs. |
| **Limitation** | Predicts exploitation probability, not business impact. A CVE with 90% EPSS but no presence in your stack is irrelevant. Must be combined with asset context and reachability data. 30-day window may miss slower exploitation campaigns. |
| **Relevance to our project** | EPSS is directly integrable into our AI triage layer via its free API. Instead of relying solely on CVSS scores (which poorly predict exploitation — AUPRC of only 0.011), we can use EPSS probability as a key feature in our prioritisation model. This gives our tool a data-driven edge over simple severity-based sorting. |

**Notes / Quotes:**
> CVSS tells you how BAD a vulnerability could be. EPSS tells you how LIKELY it is to be exploited. Our triage system should use both: EPSS for urgency (is this being exploited now?) and CVSS for impact (how bad if exploited?). Together they give a much better risk picture than either alone.

---

## Entry 5 — CISA SSVC (Stakeholder-Specific Vulnerability Categorization)

| Field | Content |
|---|---|
| **Full title** | Stakeholder-Specific Vulnerability Categorization (SSVC) |
| **Authors / Creator** | CISA (Cybersecurity and Infrastructure Security Agency), originally developed at Carnegie Mellon SEI |
| **Year** | 2020 (v1), continuously updated |
| **Venue** | Government framework / methodology |
| **URL / DOI** | https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc |
| **Method** | Decision-tree methodology for vulnerability prioritisation based on stakeholder context. Four decision points: (1) Exploitation status — is it being exploited? (2) Automatable — can the attack be automated? (3) Technical Impact — partial or total? (4) Mission & Wellbeing — how critical is the affected system? Outputs one of four actions: Track, Track*, Attend, Act. |
| **Dataset** | Uses CISA KEV (Known Exploited Vulnerabilities) catalog, EPSS scores, and organisation-specific asset data as inputs |
| **Key result** | Adopted by US federal agencies as the standard prioritisation framework. Outperforms pure CVSS-based prioritisation because it incorporates real-world exploitation context and organisational impact. Decision outputs are actionable (Track/Attend/Act) rather than numeric scores. |
| **Limitation** | Requires organisational context (asset criticality, mission relevance) that must be manually defined. Decision trees can be rigid — edge cases may not fit cleanly. Not automated out-of-the-box — needs tooling around it. |
| **Relevance to our project** | SSVC provides the decision logic for our AI triage. We can automate the SSVC decision tree: feed in EPSS scores (exploitation status), Trivy findings (technical impact), and Kubernetes metadata (is this pod internet-facing? what namespace? what RBAC permissions?) to auto-classify each vulnerability as Track/Attend/Act. This gives our tool a methodologically sound, government-endorsed framework rather than arbitrary AI scoring. |

**Notes / Quotes:**
> SSVC is the "brain" behind our prioritisation logic. EPSS answers "will this be exploited?" Kubernetes context answers "does this matter for our deployment?" SSVC combines them into actionable decisions. Our AI layer automates what SSVC currently requires humans to do manually.

---

## Reference Table (Quick Overview)

| # | Title (short) | Authors / Creator | Year | Type | Key Feature | Relevance |
|---|---|---|---|---|---|---|
| 1 | Trivy | Aqua Security | 2019+ | OSS Scanner | Container/K8s vulnerability scanning | Core scanning engine in our pipeline |
| 2 | Snyk Container | Snyk Ltd. | 2018+ | Commercial SaaS | AI-driven prioritisation + auto-fix PRs | Primary competitor — reference for UX |
| 3 | Wiz | Wiz Inc. (Google) | 2020+ | Commercial Platform | Attack path analysis, AI agents | Gold standard for contextual risk |
| 4 | EPSS | FIRST.org (Jacobs et al.) | 2023+ | ML Framework | Exploit probability prediction (0–1) | Direct integration via free API |
| 5 | SSVC | CISA / CMU SEI | 2020+ | Decision Framework | Stakeholder-specific prioritisation | Decision logic for our triage system |

---

## Tools and Datasets Identified

| Name | Type | URL | Notes |
|---|---|---|---|
| Trivy | Scanner Tool | https://github.com/aquasecurity/trivy | Primary vulnerability scanner — JSON output feeds our AI layer |
| Falco | Runtime Tool | https://falco.org/ | CNCF runtime security — detects anomalous container behavior |
| OPA Gatekeeper | Policy Tool | https://open-policy-agent.github.io/gatekeeper/ | Kubernetes admission controller — enforces security policies |
| NVD API | Dataset | https://services.nvd.nist.gov/rest/json/cves/2.0 | 357k+ CVEs with CVSS scores — training/reference data |
| EPSS API | Dataset/Model | https://www.first.org/epss/ | Daily exploit probability scores for all CVEs — free API |
| CISA KEV | Dataset | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Known exploited vulnerabilities — ground truth for "is this being exploited?" |
| Grype | Scanner Tool | https://github.com/anchore/grype | Alternative to Trivy — useful for comparison/validation |
