# Literature Review: DevSecOps AI Pipeline with Kubernetes Security Scanning

**Student:** Abdul Hadi
**Updated:** 2026-06-21

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

## Entry 6 — EPSS Paper (Jacobs et al., 2023)

| Field | Content |
|---|---|
| **Full title** | Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights |
| **Authors** | Jay Jacobs, Sasha Romanosky, Octavian Suciu, Benjamin Edwards, Armin Sarabi |
| **Year** | 2023 |
| **Venue** | IEEE European Symposium on Security and Privacy Workshops (EuroS&PW 2023) |
| **URL / DOI** | DOI: 10.1109/EuroSPW59617.2023.00021 / arXiv: 2302.14172 |
| **Method** | XGBoost (gradient-boosted decision trees) trained on 1,477 features: published exploit code (Exploit-DB, GitHub, Metasploit), public vulnerability lists (CISA KEV, Google Project Zero), social media mentions (Twitter at 7/30/90 day windows), offensive security tools (Nuclei, sn1per), NVD reference counts, CVSS metrics, CWE classifications, and vendor labels. A transformer-based neural network was tested but underperformed XGBoost (AUC 0.7374 vs 0.7795). |
| **Dataset** | 192,035 published vulnerabilities (through Dec 2022); 6.4 million exploitation observations covering July 2016–Dec 2022; 12,243 unique exploited CVEs. Ground truth from Fortinet, AlienVault OTX, Shadowserver Foundation, GreyNoise. |
| **Key result** | 82% improvement in precision-recall AUC: from 0.429 (EPSS v2) to 0.779 (v3). At optimal F1 threshold: Precision 78.5%, Recall 67.8%, F1 = 0.728. Prioritises only 3.5% of all published CVEs. CVSS v3 alone achieved only 0.051 AUC — proving CVSS is a poor predictor of real exploitation. |
| **Limitation** | Relies on signature-based detection — misses undetected exploits. Biased toward network-based attacks (limited visibility into host-based, IoT, ICS/SCADA). Cannot distinguish researcher scanning from malicious exploitation. Model opacity makes feature contribution interpretation difficult. |
| **Relevance to our project** | This is the foundational paper behind the EPSS system we will integrate via API. The key insight for our project: CVSS alone (AUC 0.051) is nearly useless for predicting exploitation — we MUST use EPSS scores as a primary feature in our triage model. The XGBoost approach on vulnerability metadata is also a candidate for our own local scoring model if we want to go beyond API-only integration. |

**Notes / Quotes:**
> "CVSS was never designed to predict exploitation, yet the industry uses it as the primary prioritisation metric. EPSS fills this gap with actual predictive power." Our project directly benefits from this — instead of sorting by CVSS score, we sort by EPSS probability, immediately making our tool more accurate than 90% of existing solutions.

---

## Entry 7 — AgenticVM (Multi-Agent AI for Vulnerability Management)

| Field | Content |
|---|---|
| **Full title** | AgenticVM: Agentic AI for Adaptive Software Vulnerability Management |
| **Authors** | Asrul Arifin, Hussain Ahmad, Yiyao Zhang, Diksha Goel |
| **Year** | 2026 |
| **Venue** | arXiv preprint (arXiv:2605.01739), CC-BY-4.0 license |
| **URL / DOI** | https://doi.org/10.48550/arXiv.2605.01739 |
| **Method** | Six specialised agents orchestrated via LangGraph: (1) Detection Agent — hybrid rule-based + LLM parsing for scanners (Trivy, Snyk, Grype); (2) Assessment Agent — cross-references findings against project context; (3) Prediction Agent — BERT-small model for CVSS metric inference; (4) Integration Agent — schema validation via Pydantic; (5) Prioritisation Agent — CVSS threshold at 7.0; (6) Recommendation Agent — LLM-driven retrieval-grounded generation. Uses OpenAI gpt-4o-mini with temperature 0.0–0.1. |
| **Dataset** | 169,883 CVE records from NVD/EUVD (80/10/10 split). Evaluated on 3 microservice applications: Online Boutique (Google K8s demo), Train-Ticket (distributed system), Beer-Shop (go-kratos). |
| **Key result** | 97.9% alert reduction: Train-Ticket reduced from 3,983 raw findings to 82 prioritised items. CVSS prediction accuracy 89.3% across 8 metrics. Single-agent LLM baseline achieved only 28.5% reduction — proving multi-agent architecture outperforms monolithic approaches. Stable across reruns (8.8 ± 0.4 unique CVEs). |
| **Limitation** | External LLM dependency affects latency and cost. Dataset may not represent full diversity of real-world vulnerabilities. Workflow-level metrics rather than conventional classifier metrics. No human-centred evaluation of trust calibration yet. |
| **Relevance to our project** | This is the closest reference architecture to what we are building. Key learnings: (1) Multi-agent beats single-agent for vulnerability triage; (2) They integrate Trivy/Snyk/Grype — same scanner stack as us; (3) They evaluate on Google's Online Boutique which is a standard K8s demo app — we can use the same for benchmarking; (4) 97.9% alert reduction is the performance target for our tool. We can adopt their Detection → Assessment → Prioritisation pipeline and add EPSS + SSVC + Kubernetes context as improvements. |

**Notes / Quotes:**
> AgenticVM demonstrates that a multi-agent architecture with specialised roles (detect → assess → predict → prioritise → recommend) outperforms monolithic LLM approaches by 70%. This validates our architectural choice: separate agents/modules for scanning, enrichment, scoring, and reporting rather than a single prompt-based system.

---

## Entry 8 — LLMSecConfig (LLM-Based Kubernetes Misconfiguration Repair)

| Field | Content |
|---|---|
| **Full title** | LLMSecConfig: An LLM-Based Approach for Fixing Software Container Misconfigurations |
| **Authors** | Ziyang Ye, Triet Huynh Minh Le, M. Ali Babar |
| **Year** | 2025 |
| **Venue** | arXiv preprint (arXiv:2502.02009) — cs.SE, cs.AI, cs.CR |
| **URL / DOI** | https://doi.org/10.48550/arXiv.2502.02009 |
| **Method** | Combines Static Analysis Tools (Checkov scanner) with LLMs (Mistral Large 2, GPT-4o-mini) using Retrieval-Augmented Generation (RAG). RAG context includes: Checkov scanner output, policy source code, and Prisma Cloud security documentation. Uses an iterative validation pipeline: syntax check → security validation → two-stage retry mechanism (outer loop max 5 attempts, inner loop max 10 retries). |
| **Dataset** | 1,000 real-world misconfigured Kubernetes configuration files sourced from the top 1,000 most popular Helm charts on ArtifactHub (official CNCF repository). Helm charts converted to raw K8s YAML, filtered to only files triggering security issues. |
| **Key result** | Mistral Large 2 achieved 94.3% pass rate for automated security fix generation (vs. 40.2% for GPT-4o-mini). 100% parse success rate. Average only 0.024 new errors introduced per fix. Average 3.06 retry steps to reach a valid fix. |
| **Limitation** | Evaluated only on Kubernetes configs — may not generalise to other orchestrators. Privilege-related security contexts and advanced network policies remain challenging. Only two LLMs compared — no baseline against non-LLM automated repair tools. |
| **Relevance to our project** | Directly applicable to our pipeline's remediation stage. After our SSVC triage identifies "Act" findings, we could use a similar LLM+RAG approach to automatically generate fix suggestions for Kubernetes misconfigurations. Their SAT→LLM→validation pipeline mirrors our Trivy→AI→report architecture. The 94.3% success rate proves LLMs can reliably fix container security issues when given proper RAG context — this is the auto-remediation feature we can add as a stretch goal. |

**Notes / Quotes:**
> LLMSecConfig proves that LLMs with proper RAG context can fix Kubernetes security issues at 94% accuracy. This validates our approach of using AI not just for detection/triage but potentially for automated remediation. Their iterative retry + validation pattern is something we should adopt: never trust LLM output without re-scanning to confirm the fix actually resolves the vulnerability.

---

## Reference Table (Quick Overview)

| # | Title (short) | Authors / Creator | Year | Type | Key Feature | Relevance |
|---|---|---|---|---|---|---|
| 1 | Trivy | Aqua Security | 2019+ | OSS Scanner | Container/K8s vulnerability scanning | Core scanning engine in our pipeline |
| 2 | Snyk Container | Snyk Ltd. | 2018+ | Commercial SaaS | AI-driven prioritisation + auto-fix PRs | Primary competitor — reference for UX |
| 3 | Wiz | Wiz Inc. (Google) | 2020+ | Commercial Platform | Attack path analysis, AI agents | Gold standard for contextual risk |
| 4 | EPSS | FIRST.org (Jacobs et al.) | 2023+ | ML Framework | Exploit probability prediction (0–1) | Direct integration via free API |
| 5 | SSVC | CISA / CMU SEI | 2020+ | Decision Framework | Stakeholder-specific prioritisation | Decision logic for our triage system |
| 6 | EPSS Paper (Jacobs et al.) | Jacobs, Romanosky, Suciu, Edwards, Sarabi | 2023 | XGBoost ML model | 82% improvement over CVSS for exploit prediction | Foundation for our ML-based scoring |
| 7 | AgenticVM | Arifin, Ahmad, Zhang, Goel | 2026 | Multi-agent LLM + BERT | 97.9% alert reduction on microservices | Reference architecture for our AI triage |
| 8 | LLMSecConfig | Ye, Le, Babar | 2025 | LLM + RAG | 94.3% automated K8s misconfiguration fix rate | Auto-remediation approach for our pipeline |

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
