# Evidence — committed pipeline output

This directory is **committed on purpose**, unlike `experiments/results/`.

`experiments/results/` is scratch space: it is rewritten on every run, and
`.gitignore` excludes `*.json` and `*.md` there. That kept the repo clean but had a
side effect — the artifacts a reviewer most needs (the scan-cluster report, Falco
alerts, the watcher output, the cluster inventory) were **uncommittable by default**,
so integration claims could only be checked by reading code.

This directory fixes that. It holds a curated, redacted snapshot of real output:

```bash
# on the machine with the cluster, after running the pipeline stages
python scripts/collect_evidence.py --label week10
git add experiments/evidence && git commit -m "evidence: real output for <stages>"
```

`collect_evidence.py` copies a known set of artifacts here, strips the operator's
username, the hostname and anything key-shaped, and writes `MANIFEST.md` recording
the command that produced each file.

Two rules for this directory:

1. **Nothing here is hand-written.** Every file is real tool output. If a stage was
   not run, its artifact is absent and the manifest says so — absence means *not
   run*, never *failed*, and never a placeholder standing in for a real result.
2. **Redaction is one-way.** Artifacts are passed through the redactor before they
   land here. Never copy a file in by hand.
