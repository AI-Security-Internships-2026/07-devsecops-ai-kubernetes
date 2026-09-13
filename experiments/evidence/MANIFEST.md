# Evidence — real pipeline output

Collected 2026-09-01 05:57 UTC · label `week10`

Committed so the integration paths can be reviewed as *output*, not just as code.
Every file is produced by the command listed beside it and passed through
`scripts/collect_evidence.py`, which strips the operator's username, the
hostname and anything key-shaped. Regenerate with:

```bash
python scripts/collect_evidence.py --label <tag>
```

| Artifact | Produced by | What it shows | Size |
|---|---|---|---|
| `scan_cluster_report.md` | `python run.py scan-cluster --namespace default` | Cluster-wide triage: every running image, with Act/Attend/Track counts. | 412 bytes, verbatim |
| `scan_cluster_report.json` | `python run.py scan-cluster --namespace default` | Machine-readable form of the same cluster report. | 1,064 bytes, verbatim |
| `cluster_inventory.json` | `python run.py discover` | Pods, images, phase, exposure and privilege - the K8s context input. | 3,595 bytes, verbatim |
| `falco_alerts.json` | `python run.py falco-capture --live` | Normalised Falco runtime alerts as the tool consumes them. | 21,225 bytes, verbatim |
| `falco_captured.jsonl` | `bash scripts/falco_setup.sh capture 45` | Raw Falco JSONL exactly as the kernel probe emitted it. | 37,374 bytes, verbatim |
| `cve_watch_alerts.md` | `python run.py watch` | Fresh-CVE watcher output: SBOM x feed matches. | 70,462 bytes, verbatim |
| `triage_run.json` | `python run.py pipeline <image>` | Most recent single-image triage run. — vuln-demo:1.0: 175 CVEs, Act 4, Attend 15, reduction 89.1% | 120,462 bytes, verbatim |
| `eval.md` | `python scripts/evaluate_triage.py experiments/results --out eval` | Evaluation tables: baselines, KEV recall, context/runtime effect, attribution. | 3,251 bytes, verbatim |
| `eval.json` | `python scripts/evaluate_triage.py experiments/results --out eval` | Machine-readable evaluation results. | 4,174 bytes, verbatim |
| `triage_run_nginx_1.21.json` | `python run.py pipeline <image>` | Per-image triage output - the file every evaluation number is computed from. — nginx:1.21: 493 CVEs, Act 34, Attend 71, reduction 78.7% | 327,980 bytes, verbatim |
| `triage_run_nginx_latest.json` | `python run.py pipeline <image>` | Per-image triage output - the file every evaluation number is computed from. — nginx:latest: 140 CVEs, Act 5, Attend 5, reduction 92.9% | 92,858 bytes, verbatim |
| `triage_run_redis_6.2.json` | `python run.py pipeline <image>` | Per-image triage output - the file every evaluation number is computed from. — redis:6.2: 85 CVEs, Act 2, Attend 6, reduction 90.6% | 56,292 bytes, verbatim |
| `triage_run_vuln-demo_1.0.json` | `python run.py pipeline <image>` | Per-image triage output - the file every evaluation number is computed from. — vuln-demo:1.0: 175 CVEs, Act 4, Attend 15, reduction 89.1% | 120,462 bytes, verbatim |
| `gatekeeper_vuln-demo_1.0.yaml` | `python run.py pipeline <image> --gatekeeper` | Generated OPA Gatekeeper policy (generate-only; nothing applies it). | 3,381 bytes, verbatim |
