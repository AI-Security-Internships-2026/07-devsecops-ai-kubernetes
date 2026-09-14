#!/usr/bin/env bash
#
# falco_attributable_capture.sh - capture Falco alerts that can actually escalate a
#                                 finding, for the runtime attribution study (issue #25).
#
# The problem this solves
# ----------------------
# The previous capture produced 20 real alerts and zero escalations, for two reasons that
# are easy to repeat:
#
#   1. Every alert that matched a triaged image was WARNING level. Only critical-tier
#      alerts (Emergency/Alert/Critical/Error) are escalation candidates; lower tiers
#      annotate by design.
#   2. The two Critical alerts carried NO container image, because they were triggered
#      from a throwaway pod and from host-level activity. An alert with no image matches
#      no finding.
#
# So an attributable alert needs all three of: critical tier, a container image that is
# actually being triaged, and a process that maps to a package the image's CVEs affect.
# This script drives activity INSIDE the real workload containers and reports which of
# the three conditions each resulting alert satisfies, rather than just counting alerts.
#
# Usage
# -----
#   bash scripts/falco_attributable_capture.sh                    # default namespace
#   bash scripts/falco_attributable_capture.sh -n default -s 60   # namespace, seconds
#   bash scripts/falco_attributable_capture.sh --dry-run          # show what it would do
#
# Output: experiments/results/falco_attributable.jsonl  (feed to --falco)
#
# CRLF note: if you see "$'\r'", run: sed -i 's/\r$//' scripts/falco_attributable_capture.sh
#
set -uo pipefail

NS="default"
FALCO_NS="falco"
SECS=60
DRY_RUN="false"

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) NS="$2"; shift 2 ;;
    --falco-namespace) FALCO_NS="$2"; shift 2 ;;
    -s|--seconds) SECS="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[0m'; G=$'\033[32m'; Y=$'\033[33m'; E=$'\033[31m'
else B=""; R=""; G=""; Y=""; E=""; fi
hdr(){ printf '\n%s== %s ==%s\n' "$B" "$1" "$R"; }
ok(){  printf '  %s[ok]%s   %s\n' "$G" "$R" "$1"; }
warn(){ printf '  %s[warn]%s %s\n' "$Y" "$R" "$1"; }
bad(){ printf '  %s[fail]%s %s\n' "$E" "$R" "$1"; }
inf(){ printf '  [..]   %s\n' "$1"; }

command -v kubectl >/dev/null 2>&1 || { bad "kubectl not found"; exit 1; }

OUT_DIR="experiments/results"
RAW="$OUT_DIR/falco_attributable_raw.jsonl"
OUT="$OUT_DIR/falco_attributable.jsonl"
mkdir -p "$OUT_DIR"

falco_pod(){ kubectl get pods -n "$FALCO_NS" -l app.kubernetes.io/name=falco \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }

# Triggers chosen to fire CRITICAL-TIER rules from Falco's default ruleset, and to use
# processes whose owning package is resolvable by src/runtime/attribution.py:
#
#   touch /bin/<f>        -> "Write below binary dir"            (ERROR)   proc: touch    -> coreutils
#   cp /bin/sh /bin/<f>   -> "Write below binary dir"            (ERROR)   proc: cp       -> coreutils
#   /tmp copy + exec      -> "Drop and execute new binary in container" (CRITICAL)
#   chmod on a bin path   -> "Write below binary dir"            (ERROR)   proc: chmod    -> coreutils
#
# `cat /etc/shadow` is deliberately NOT used alone: it fires "Read sensitive file
# untrusted" at WARNING, which annotates but cannot escalate - that is what the previous
# capture collected.
#
# Both outcomes are useful for issue #25. `touch`/`chmod`/`cp` resolve to coreutils, so a
# finding in coreutils should escalate. The dropped binary in /tmp resolves to no package
# at all, which should annotate and never escalate - the conservative path, and a case
# Table F2 needs in order to report attribution behaviour by evidence type.
trigger_in_pod(){
  local pod="$1"
  kubectl exec -n "$NS" "$pod" -- sh -c '
    touch /bin/falco-probe 2>/dev/null
    chmod 755 /bin/falco-probe 2>/dev/null
    cp /bin/sh /bin/falco-probe2 2>/dev/null
    cp /bin/sh /tmp/falco-dropped 2>/dev/null
    chmod +x /tmp/falco-dropped 2>/dev/null
    /tmp/falco-dropped -c "true" 2>/dev/null
    cat /etc/shadow >/dev/null 2>&1
    rm -f /bin/falco-probe /bin/falco-probe2 /tmp/falco-dropped 2>/dev/null
    true
  ' >/dev/null 2>&1
  return 0
}

hdr "target workloads in namespace '$NS'"
PODS="$(kubectl get pods -n "$NS" --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)"
[ -z "$PODS" ] && { bad "no Running pods in namespace '$NS'"; exit 1; }
for p in $PODS; do
  img="$(kubectl get pod "$p" -n "$NS" -o jsonpath='{.spec.containers[0].image}' 2>/dev/null)"
  inf "$p  ($img)"
done

if [ "$DRY_RUN" = "true" ]; then
  hdr "dry run"
  echo "  Would exec the trigger sequence in each pod above and capture ${SECS}s of alerts."
  exit 0
fi

POD="$(falco_pod)"
[ -z "$POD" ] && { bad "no Falco pod in namespace '$FALCO_NS'"; exit 1; }
ok "falco pod: $POD"

hdr "capturing ${SECS}s"
kubectl logs -f "$POD" -n "$FALCO_NS" -c falco --since=1s >"$RAW" 2>/dev/null &
FPID=$!
sleep 3

for p in $PODS; do
  inf "triggering in $p ..."
  trigger_in_pod "$p"
  sleep 2
done

waited=$(( 3 + $(echo "$PODS" | wc -w) * 2 ))
while [ "$waited" -lt "$SECS" ]; do sleep 5; waited=$((waited+5)); done
kill "$FPID" >/dev/null 2>&1; wait "$FPID" 2>/dev/null

grep '"priority"' "$RAW" > "$OUT" 2>/dev/null
N="$(wc -l < "$OUT" 2>/dev/null | tr -d ' ')"
[ "${N:-0}" -eq 0 ] && { bad "no JSON alerts captured"; exit 1; }
ok "$N alert(s) -> $OUT"

# ---------------------------------------------------------------------------
# Report against the three conditions an alert must meet to escalate anything.
# Counting alerts alone is what hid the problem last time.
# ---------------------------------------------------------------------------
hdr "are these alerts ESCALATION-CAPABLE?"
python3 - "$OUT" <<'PY'
import json, sys, collections

CRIT = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR"}
rows = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        o = json.loads(line)
    except json.JSONDecodeError:
        continue
    f = o.get("output_fields", {}) or {}
    repo, tag = f.get("container.image.repository"), f.get("container.image.tag")
    rows.append({
        "priority": o.get("priority", ""),
        "rule": o.get("rule", ""),
        "image": f"{repo}:{tag}" if repo and tag else (repo or ""),
        "proc": f.get("proc.name", ""),
        "exepath": f.get("proc.exepath", ""),
    })

print(f"  {len(rows)} alert(s) parsed\n")
print(f"  {'PRIORITY':<10}{'IMAGE':<22}{'PROCESS':<20}{'TIER':<16}RULE")
print("  " + "-" * 100)
capable = 0
for r in sorted(rows, key=lambda r: (r["priority"], r["image"])):
    is_crit = r["priority"].upper() in CRIT
    has_img = bool(r["image"])
    if is_crit and has_img:
        tier, capable = "ESCALATES", capable + 1
    elif is_crit:
        tier = "crit, no image"
    else:
        tier = "annotate-only"
    print(f"  {r['priority']:<10}{(r['image'] or '-'):<22}{(r['proc'] or '-'):<20}"
          f"{tier:<16}{r['rule'][:40]}")

print()
by_img = collections.Counter(r["image"] for r in rows
                             if r["priority"].upper() in CRIT and r["image"])
if capable:
    print(f"  [ok] {capable} escalation-capable alert(s) on: "
          + ", ".join(f"{k} x{v}" for k, v in by_img.items()))
    procs = sorted({r["exepath"] or r["proc"] for r in rows
                    if r["priority"].upper() in CRIT and r["image"]})
    print(f"       processes: {', '.join(p for p in procs if p)}")
    print("       -> these can attribute to a package and escalate a matching finding.")
else:
    print("  [fail] NO escalation-capable alerts. Either no critical-tier rule fired,")
    print("         or the ones that did carried no container image. Attribution will")
    print("         again measure zero. Check the rule list and container write perms.")
PY

hdr "next"
echo "  python run.py pipeline <image> --falco $OUT"
echo "  python scripts/evaluate_triage.py experiments/results --out experiments/results/eval"
