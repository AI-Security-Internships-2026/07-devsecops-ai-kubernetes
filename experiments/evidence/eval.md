# Triage Evaluation

Images evaluated: 4  -  definitions in the script header.

## 1. Volume & alert reduction (our tool)

| Image | CVEs | Act | Attend | Track* | Track | Reduction |
|-------|-----:|----:|-------:|-------:|------:|----------:|
| `nginx:1.21` | 493 | 34 | 71 | 95 | 293 | 78.7% |
| `nginx:latest` | 140 | 5 | 5 | 16 | 114 | 92.9% |
| `redis:6.2` | 85 | 2 | 6 | 8 | 69 | 90.6% |
| `vuln-demo:1.0` | 175 | 4 | 15 | 19 | 137 | 89.1% |

## 2. Baseline comparison - actionable set size & reduction

Smaller actionable set = less analyst load. Read alongside section 3 (recall).


**nginx:1.21** (493 CVEs)

| Method | Actionable | Reduction | KEV recall |
|--------|-----------:|----------:|-----------:|
| CVSS-only (sev>=HIGH) | 142 | 71.2% | 100% |
| EPSS-only (>=0.1) | 26 | 94.7% | 100% |
| Ours (Act+Attend) | 105 | 78.7% | 100% |

**nginx:latest** (140 CVEs)

| Method | Actionable | Reduction | KEV recall |
|--------|-----------:|----------:|-----------:|
| CVSS-only (sev>=HIGH) | 23 | 83.6% | n/a |
| EPSS-only (>=0.1) | 1 | 99.3% | n/a |
| Ours (Act+Attend) | 10 | 92.9% | n/a |

**redis:6.2** (85 CVEs)

| Method | Actionable | Reduction | KEV recall |
|--------|-----------:|----------:|-----------:|
| CVSS-only (sev>=HIGH) | 12 | 85.9% | n/a |
| EPSS-only (>=0.1) | 1 | 98.8% | n/a |
| Ours (Act+Attend) | 8 | 90.6% | n/a |

**vuln-demo:1.0** (175 CVEs)

| Method | Actionable | Reduction | KEV recall |
|--------|-----------:|----------:|-----------:|
| CVSS-only (sev>=HIGH) | 43 | 75.4% | n/a |
| EPSS-only (>=0.1) | 2 | 98.9% | n/a |
| Ours (Act+Attend) | 19 | 89.1% | n/a |

## 3. KEV recall (ground truth = CISA KEV)

Does each method keep the *known-exploited* CVEs in its actionable set? A method that reduces volume but drops KEV items is worse, not better.

| Image | KEV CVEs | CVSS-only | EPSS-only | Ours |
|-------|---------:|:---------:|:---------:|:----:|
| `nginx:1.21` | 4 | 100% | 100% | 100% |
| `nginx:latest` | 0 | n/a | n/a | n/a |
| `redis:6.2` | 0 | n/a | n/a | n/a |
| `vuln-demo:1.0` | 0 | n/a | n/a | n/a |

## 4. Context / runtime effect on the Act tier

How the K8s-context + Falco-runtime refinements re-ranked findings (the escalation-capping fix keeps this bounded - at most one level each).

| Image | Act before | Act after | Escalated->CRIT | De-escalated | Capped | via context | via runtime | via exploit |
|-------|-----------:|----------:|----------------:|-------------:|-------:|------------:|------------:|------------:|
| `nginx:1.21` | 26 | 34 | 8 | 0 | 0 | 11 | 493 | 2 |
| `nginx:latest` | 1 | 5 | 4 | 0 | 0 | 5 | 140 | 0 |
| `redis:6.2` | 1 | 2 | 1 | 0 | 0 | 3 | 85 | 0 |
| `vuln-demo:1.0` | 2 | 4 | 2 | 0 | 0 | 3 | 175 | 1 |

## 5. Runtime attribution (issue #17)

The runtime signal escalates a finding only when the Falco alert's process/file evidence resolves to a package that finding affects. Alerts that cannot be attributed are recorded and ignored, so this table states how often the link was actually established.

| Image | Attributed | Not attributable | Attribution rate |
|-------|-----------:|-----------------:|-----------------:|
| `nginx:1.21` | 0 | 0 | n/a |
| `nginx:latest` | 0 | 0 | n/a |
| `redis:6.2` | 0 | 0 | n/a |
| `vuln-demo:1.0` | 0 | 0 | n/a |
