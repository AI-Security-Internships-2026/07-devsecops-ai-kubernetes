#!/usr/bin/env bash
#
# falco_setup.sh - detect, install, configure, verify and capture Falco on any
#                  architecture (arm64 / x86_64), for this tool's runtime signal.
#
# Why this exists
# ---------------
# The runtime tier of our SSVC engine needs Falco to emit JSON alerts that
# `run.py falco-capture --live` can read from the Falco pod's stdout. Three things
# have to be true at once, and getting any one wrong looks identical from outside
# ("no alerts"):
#
#   1. The DRIVER must load    - no driver => no syscall events => no alerts, ever.
#   2. JSON output must be ON  - alerts exist but we can't parse the text form.
#   3. A RULE must actually FIRE - Falco is silent on an idle cluster. Silence is
#                                  the normal, healthy state. This is the one most
#                                  often mistaken for a broken install.
#
# This script settles all three, picks the right driver for the host it runs on,
# and proves the result by triggering a real rule and watching for the JSON.
#
# Usage
# -----
#   bash scripts/falco_setup.sh detect            # what's installed + what this host supports
#   bash scripts/falco_setup.sh install           # install with the best driver for this host
#   bash scripts/falco_setup.sh reinstall         # clean uninstall, then install
#   bash scripts/falco_setup.sh uninstall
#   bash scripts/falco_setup.sh verify            # fire a rule, prove JSON alerts appear
#   bash scripts/falco_setup.sh capture [SECONDS] # generate activity + save alerts (default 45)
#   bash scripts/falco_setup.sh doctor            # detect + verify, full report to a file
#
# Options
#   --namespace NS     Falco namespace            (default: falco)
#   --driver KIND      force modern_ebpf|ebpf|kmod (default: auto-detect + fallback)
#   --k8s-meta         enable the k8smeta plugin so alerts carry k8s.pod.name/k8s.ns.name
#                      (optional: image matching uses container.image.* which is always present)
#   --yes              don't prompt on uninstall/reinstall
#
# CRLF note: if you see "$'\r': command not found", run: sed -i 's/\r$//' scripts/falco_setup.sh
#
set -uo pipefail

NS="falco"
FORCE_DRIVER=""
K8S_META="false"
ASSUME_YES="false"
RELEASE="falco"
SELECTOR="app.kubernetes.io/name=falco"
CONTAINER="falco"
# Driver preference order. modern_ebpf is CO-RE: no kernel headers, no compile,
# and identical behaviour on arm64 and x86_64 - which is exactly what we want for
# a tool that must run on both. The others are fallbacks.
DRIVER_ORDER="modern_ebpf ebpf kmod"

CMD="${1:-detect}"; shift || true
CAPTURE_SECS=45
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace) NS="$2"; shift 2 ;;
    --driver)    FORCE_DRIVER="$2"; shift 2 ;;
    --k8s-meta)  K8S_META="true"; shift ;;
    --yes|-y)    ASSUME_YES="true"; shift ;;
    [0-9]*)      CAPTURE_SECS="$1"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- output helpers
if [ -t 1 ]; then B=$'\033[1m'; R=$'\033[0m'; G=$'\033[32m'; Y=$'\033[33m'; E=$'\033[31m'
else B=""; R=""; G=""; Y=""; E=""; fi
hdr(){ printf '\n%s== %s ==%s\n' "$B" "$1" "$R"; }
ok(){  printf '  %s[ok]%s   %s\n' "$G" "$R" "$1"; }
warn(){ printf '  %s[warn]%s %s\n' "$Y" "$R" "$1"; }
bad(){ printf '  %s[fail]%s %s\n' "$E" "$R" "$1"; }
inf(){ printf '  [..]   %s\n' "$1"; }

need(){ command -v "$1" >/dev/null 2>&1 || { bad "$1 not found on PATH"; return 1; }; }

confirm(){
  [ "$ASSUME_YES" = "true" ] && return 0
  printf '  %s? %s [y/N] ' "$B" "$1"; read -r a 2>/dev/null || return 1
  case "$a" in y|Y|yes) return 0 ;; *) return 1 ;; esac
}

# ------------------------------------------------------------------ host probing
ARCH="$(uname -m)"
KREL="$(uname -r)"
kver_ge(){ # kver_ge 5 8  -> true if running kernel >= 5.8
  local maj min want_maj="$1" want_min="$2"
  maj="${KREL%%.*}"; min="${KREL#*.}"; min="${min%%.*}"
  [ "${maj:-0}" -gt "$want_maj" ] && return 0
  [ "${maj:-0}" -eq "$want_maj" ] && [ "${min:-0}" -ge "$want_min" ] && return 0
  return 1
}
has_btf(){ [ -r /sys/kernel/btf/vmlinux ]; }
has_headers(){ [ -d "/lib/modules/$KREL/build" ] || [ -d "/usr/src/linux-headers-$KREL" ]; }

pick_driver(){
  if [ -n "$FORCE_DRIVER" ]; then echo "$FORCE_DRIVER"; return; fi
  if kver_ge 5 8 && has_btf; then echo "modern_ebpf"; return; fi
  if kver_ge 4 14; then echo "ebpf"; return; fi
  echo "kmod"
}

falco_pod(){ kubectl get pods -n "$NS" -l "$SELECTOR" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }

installed(){ helm status "$RELEASE" -n "$NS" >/dev/null 2>&1; }

# ------------------------------------------------------------------------ detect
do_detect(){
  hdr "host"
  inf "arch=$ARCH  kernel=$KREL"
  if has_btf; then ok "BTF present (/sys/kernel/btf/vmlinux) - modern_ebpf (CO-RE) supported"
  else warn "no BTF - modern_ebpf unavailable; will fall back to ebpf/kmod"; fi
  if has_headers; then ok "kernel headers present - ebpf/kmod can build"
  else warn "no kernel headers for $KREL - kmod/legacy ebpf may fail"; fi
  inf "driver this host should use: $(pick_driver)"

  hdr "tooling"
  for t in kubectl helm; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t $( "$t" version --short 2>/dev/null | head -1)"
    else bad "$t missing"; fi
  done

  hdr "cluster / falco release"
  if ! kubectl cluster-info >/dev/null 2>&1; then
    bad "no reachable Kubernetes cluster"; return 1
  fi
  ok "cluster reachable"
  if installed; then
    ok "helm release '$RELEASE' installed in namespace '$NS'"
    helm list -n "$NS" 2>/dev/null | sed 's/^/     /'
  else
    warn "no helm release '$RELEASE' in '$NS' - run: bash scripts/falco_setup.sh install"
    return 0
  fi

  hdr "pods"
  kubectl get pods -n "$NS" -o wide 2>&1 | sed 's/^/     /'
  local pod; pod="$(falco_pod)"
  [ -z "$pod" ] && { bad "no Falco pod matched selector '$SELECTOR'"; return 1; }
  ok "pod: $pod"
  local phase; phase="$(kubectl get pod "$pod" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)"
  if [ "$phase" = "Running" ]; then
    ok "phase=Running -> the driver-loader init container succeeded, so a driver IS loaded"
  else
    bad "phase=$phase - if this is Init:* the driver failed to load (that IS the problem)"
  fi

  hdr "effective config (what our tool depends on)"
  local kind
  kind="$(kubectl get ds -n "$NS" -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{range .env[*]}{.name}={.value}{"\n"}{end}{end}{end}' 2>/dev/null | grep -i 'DRIVER\|BPF' | head -3)"
  [ -n "$kind" ] && inf "driver env: $kind"
  local cfg
  cfg="$(kubectl get cm -n "$NS" -o yaml 2>/dev/null | grep -E 'json_output|buffered_outputs|json_include_output_property' | sort -u)"
  if echo "$cfg" | grep -q 'json_output: true'; then ok "json_output: true"
  else bad "json_output is NOT true - our parser needs JSON (reinstall to fix)"; fi
  if echo "$cfg" | grep -q 'buffered_outputs: false'; then ok "buffered_outputs: false (alerts flush immediately)"
  else warn "buffered_outputs not false - live capture may see delayed/absent output"; fi

  hdr "recent driver/rule log lines"
  kubectl logs "$pod" -n "$NS" -c "$CONTAINER" --tail=200 2>/dev/null \
    | grep -i -E 'driver|probe|BPF|BTF|kmod|CO-RE|Loading rules|initialized|Starting|error|fail' \
    | tail -12 | sed 's/^/     /' || warn "no matching log lines"

  hdr "verdict"
  echo "  Driver state and config are shown above. Silence is NOT proof of failure -"
  echo "  Falco only speaks when a rule fires. Prove it end-to-end with:"
  echo "      bash scripts/falco_setup.sh verify"
}

# ----------------------------------------------------------------------- install
helm_install(){
  local kind="$1"
  inf "installing Falco with driver.kind=$kind ..."
  helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1
  helm repo update >/dev/null 2>&1

  # Only the values this tool actually depends on:
  #   driver.kind        - which probe collects syscalls
  #   tty                - unbuffered stdout, or lines can sit in a pipe buffer
  #   json_output        - our parser reads JSONL; text output is unusable
  #   buffered_outputs   - false => flush per alert, so `kubectl logs` is live
  #   stdout_output      - we scrape pod stdout, so this must be on
  #   priority           - informational and above; our two-tier model filters itself
  local args=(
    --namespace "$NS" --create-namespace
    --set "driver.kind=$kind"
    --set tty=true
    --set falco.json_output=true
    --set falco.json_include_output_property=true
    --set falco.json_include_tags_property=true
    --set falco.buffered_outputs=false
    --set falco.stdout_output.enabled=true
    --set falco.priority=informational
  )
  # k8s.* fields need the k8smeta plugin. Optional: image matching uses
  # container.image.repository/tag, which the container collector always provides.
  if [ "$K8S_META" = "true" ]; then
    args+=( --set collectors.kubernetes.enabled=true )
  fi

  helm upgrade --install "$RELEASE" falcosecurity/falco "${args[@]}" 2>&1 | tail -5 | sed 's/^/     /'
}

wait_ready(){
  inf "waiting for Falco pods to become Ready (up to 180s)..."
  if kubectl wait --for=condition=ready pod -l "$SELECTOR" -n "$NS" --timeout=180s >/dev/null 2>&1; then
    ok "Falco pods Ready"; return 0
  fi
  bad "Falco pods did not become Ready"
  kubectl get pods -n "$NS" 2>&1 | sed 's/^/     /'
  local pod; pod="$(falco_pod)"
  if [ -n "$pod" ]; then
    inf "driver-loader output:"
    kubectl logs "$pod" -n "$NS" -c falco-driver-loader --tail=25 2>/dev/null | sed 's/^/     /'
  fi
  return 1
}

do_install(){
  need kubectl || return 1; need helm || return 1
  kubectl cluster-info >/dev/null 2>&1 || { bad "no reachable cluster"; return 1; }

  local order="$DRIVER_ORDER"
  [ -n "$FORCE_DRIVER" ] && order="$FORCE_DRIVER"
  # Skip drivers this host obviously can't run, so we don't burn 3 minutes proving it.
  if [ -z "$FORCE_DRIVER" ] && ! has_btf; then
    order="$(echo "$order" | sed 's/modern_ebpf//')"
    warn "no BTF on this host - skipping modern_ebpf"
  fi

  for kind in $order; do
    hdr "attempt: driver.kind=$kind"
    if installed; then helm uninstall "$RELEASE" -n "$NS" >/dev/null 2>&1; sleep 5; fi
    helm_install "$kind"
    if ! wait_ready; then
      warn "driver '$kind' did not come up - trying the next one"
      continue
    fi
    if do_verify quiet; then
      hdr "result"
      ok "Falco installed with driver.kind=$kind and VERIFIED emitting JSON alerts"
      echo "  Next: python run.py falco-capture --live"
      return 0
    fi
    warn "driver '$kind' loaded but produced no JSON alert - trying the next one"
  done

  hdr "result"
  bad "no driver produced JSON alerts on this host ($ARCH, kernel $KREL)"
  echo "  Run 'bash scripts/falco_setup.sh detect' and share the output."
  echo "  Fallback for demos: feed a captured file with 'python run.py pipeline <img> --falco <file>'."
  return 1
}

do_uninstall(){
  need helm || return 1
  installed || { warn "no release '$RELEASE' in '$NS' - nothing to remove"; return 0; }
  confirm "uninstall Falco release '$RELEASE' from namespace '$NS'?" || { inf "aborted"; return 1; }
  helm uninstall "$RELEASE" -n "$NS" 2>&1 | sed 's/^/     /'
  # The namespace is ours (created by --create-namespace); remove it only if empty.
  if [ -z "$(kubectl get all -n "$NS" 2>/dev/null | head -2 | tail -1)" ]; then
    kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 && inf "namespace '$NS' deleted"
  fi
  ok "uninstalled"
}

# ------------------------------------------------------------------------ verify
# Fire a rule on purpose and watch for a JSON alert. This is the only honest test:
# it separates "Falco is broken" from "nothing happened, so Falco stayed quiet".
trigger_activity(){
  local tag="$1"
  # Three chances at well-known default rules:
  #   read /etc/shadow      -> "Read sensitive file untrusted"
  #   write below /bin      -> "Write below binary dir"
  #   spawn a shell         -> "Terminal shell in container" (needs a tty; best-effort)
  kubectl run "falco-trigger-$tag" --image=busybox:1.35 --restart=Never \
    -n default --command -- sh -c \
    'cat /etc/shadow >/dev/null 2>&1; touch /bin/falco-probe 2>/dev/null; \
     ls /bin/falco-probe >/dev/null 2>&1; echo triggered; sleep 2' >/dev/null 2>&1
}

cleanup_trigger(){ kubectl delete pod "falco-trigger-$1" -n default --now >/dev/null 2>&1 || true; }

do_verify(){
  local quiet="${1:-}"
  need kubectl || return 1
  local pod; pod="$(falco_pod)"
  [ -z "$pod" ] && { bad "no Falco pod found in '$NS'"; return 1; }

  [ "$quiet" = "quiet" ] || hdr "verify: firing a rule and watching for JSON"
  local tag stream
  tag="$(date +%s)"
  stream="$(mktemp)"

  # Follow first, then trigger, so we cannot miss the alert.
  kubectl logs -f "$pod" -n "$NS" -c "$CONTAINER" --since=1s >"$stream" 2>/dev/null &
  local fpid=$!
  sleep 3
  trigger_activity "$tag"
  sleep 12
  cleanup_trigger "$tag"
  kill "$fpid" >/dev/null 2>&1; wait "$fpid" 2>/dev/null

  local n_json
  n_json="$(grep -c '"priority"' "$stream" 2>/dev/null)"
  if [ "${n_json:-0}" -gt 0 ]; then
    ok "$n_json JSON alert line(s) captured - Falco is working end to end"
    if [ "$quiet" != "quiet" ]; then
      inf "rules that fired:"
      grep -o '"rule":"[^"]*"' "$stream" | sort | uniq -c | sed 's/^/     /'
      inf "sample alert:"
      grep '"priority"' "$stream" | head -1 | cut -c1-220 | sed 's/^/     /'
    fi
    rm -f "$stream"; return 0
  fi

  if grep -qiE 'Warning|Notice|Critical|Error' "$stream" 2>/dev/null; then
    bad "alerts fired but NOT as JSON - json_output is off. Fix: bash scripts/falco_setup.sh reinstall"
  else
    bad "no alert at all after triggering - the driver is not delivering syscall events"
    [ "$quiet" != "quiet" ] && kubectl logs "$pod" -n "$NS" -c "$CONTAINER" --tail=30 2>/dev/null \
      | grep -iE 'driver|BPF|BTF|error|fail' | tail -8 | sed 's/^/     /'
  fi
  rm -f "$stream"; return 1
}

# ----------------------------------------------------------------------- capture
# Generate benign activity, capture the resulting alerts, and hand the pipeline a
# real (not hand-written) alert file.
do_capture(){
  need kubectl || return 1
  local pod; pod="$(falco_pod)"
  [ -z "$pod" ] && { bad "no Falco pod found in '$NS'"; return 1; }

  local out_dir="experiments/results"
  mkdir -p "$out_dir"
  local raw="$out_dir/falco_stream_raw.jsonl"
  # Deliberately NOT falco_alerts.json: `run.py falco-capture` WRITES that path
  # (in its normalised {summary, alerts} form), so reusing it here would make the
  # tool overwrite its own input and the second run would parse nothing.
  local out="$out_dir/falco_captured.jsonl"

  hdr "capture: ${CAPTURE_SECS}s of real Falco alerts"
  inf "following $pod and generating activity in demo workloads..."

  kubectl logs -f "$pod" -n "$NS" -c "$CONTAINER" --since=1s >"$raw" 2>/dev/null &
  local fpid=$!
  sleep 2

  # Exercise the demo workloads themselves, so alerts carry THEIR images - that is
  # what makes the runtime signal land on the images we triage.
  local tag; tag="$(date +%s)"
  trigger_activity "$tag"
  for p in $(kubectl get pods -n default -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' 2>/dev/null); do
    kubectl exec -n default "$p" -- sh -c \
      'cat /etc/shadow >/dev/null 2>&1; touch /bin/falco-probe 2>/dev/null; true' >/dev/null 2>&1 || true
  done

  local waited=4
  while [ "$waited" -lt "$CAPTURE_SECS" ]; do sleep 5; waited=$((waited+5)); done
  cleanup_trigger "$tag"
  kill "$fpid" >/dev/null 2>&1; wait "$fpid" 2>/dev/null

  # Keep only JSON alert lines; Falco's startup banner is not JSON.
  grep '"priority"' "$raw" > "$out" 2>/dev/null
  local n; n="$(wc -l < "$out" 2>/dev/null | tr -d ' ')"
  if [ "${n:-0}" -gt 0 ]; then
    ok "$n real alert(s) -> $out"
    inf "by priority:"; grep -o '"priority":"[^"]*"' "$out" | sort | uniq -c | sed 's/^/     /'
    inf "by image:";    grep -o '"container.image.repository":"[^"]*"' "$out" | sort | uniq -c | sed 's/^/     /'
    echo
    echo "  Use it:  python run.py pipeline <image> --falco $out"
    echo "  Or live: python run.py falco-capture --live"
  else
    bad "captured no JSON alerts in ${CAPTURE_SECS}s"
    echo "  Run 'bash scripts/falco_setup.sh verify' to find out which of the three"
    echo "  preconditions is failing (driver / json_output / rule actually firing)."
    rm -f "$out"; return 1
  fi
}

# ------------------------------------------------------------------------ doctor
do_doctor(){
  local rep="falco_doctor_$(date +%Y%m%d_%H%M%S).txt"
  { do_detect; do_verify; } 2>&1 | tee "$rep"
  echo; echo "Report written to $rep"
}

case "$CMD" in
  detect)    do_detect ;;
  install)   do_install ;;
  reinstall) do_uninstall; do_install ;;
  uninstall) do_uninstall ;;
  verify)    do_verify ;;
  capture)   do_capture ;;
  doctor)    do_doctor ;;
  *) sed -n '2,40p' "$0"; exit 2 ;;
esac
