#!/usr/bin/env bash
#
# vm_privileged_setup.sh - the only part of the setup that needs root.
#
# Run this once, with sudo, on a shared research host. Everything afterwards runs as
# your normal user, so the privileged surface stays small and auditable.
#
#   sudo bash scripts/vm_privileged_setup.sh
#
# What it does
#   1. adds the invoking user to the `microk8s` and `docker` groups
#   2. hands them their own ~/.kube
#   3. installs Trivy (the scanner) and Helm (needed to deploy Falco)
#   4. aliases `kubectl` to MicroK8s's bundled client
#
# What it deliberately does NOT do
#   * install k3s or any second Kubernetes distribution. This host already runs
#     MicroK8s; a second distribution would contend for the kubelet port and for
#     containerd, and on a shared box that breaks other people's clusters.
#   * install Falco. That is a cluster-wide privileged DaemonSet which loads an eBPF
#     program on the shared host kernel, so it is a decision for whoever owns this
#     machine, not a side effect of a setup script. Install it deliberately afterwards:
#         bash scripts/falco_setup.sh install
#   * change anything about the running MicroK8s, its addons or its workloads.
#   * touch any other user's files.
#
set -uo pipefail

TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
ARCH_DEB="$(dpkg --print-architecture 2>/dev/null || echo arm64)"
CHANGED=()

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must run as root:  sudo bash $0" >&2
  exit 1
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ ok ] %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
err()  { printf '  [fail] %s\n' "$*"; }
head2(){ printf '\n== %s\n%s\n' "$*" "$(printf '%.0s-' {1..64})"; }

say "=================================================================="
say " privileged setup for: $TARGET_USER   ($TARGET_HOME)"
say " host: $(hostname)   arch: $ARCH_DEB"
say "=================================================================="

# ------------------------------------------------------------------ 1. groups

head2 "Group membership"

for grp in microk8s docker; do
  if ! getent group "$grp" >/dev/null 2>&1; then
    warn "group '$grp' does not exist - skipping (is that component installed?)"
    continue
  fi
  if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx "$grp"; then
    ok "$TARGET_USER is already in '$grp'"
  else
    usermod -a -G "$grp" "$TARGET_USER" && {
      ok "added $TARGET_USER to '$grp'"
      CHANGED+=("group:$grp")
    }
  fi
done

# MicroK8s writes here and the directory is often root-owned from a sudo invocation,
# which then silently breaks every later non-root kubectl call.
if [ -d "$TARGET_HOME/.kube" ]; then
  chown -f -R "$TARGET_USER" "$TARGET_HOME/.kube" && ok "~/.kube is owned by $TARGET_USER"
else
  install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 0700 "$TARGET_HOME/.kube" \
    && ok "created ~/.kube"
fi

# ------------------------------------------------------------- 2. kubectl alias

head2 "kubectl"

if command -v kubectl >/dev/null 2>&1; then
  ok "kubectl already on PATH: $(command -v kubectl)"
elif command -v microk8s >/dev/null 2>&1; then
  # Prefer MicroK8s's own client: it is version-matched to the running API server,
  # which matters here because that server is v1.22.
  snap alias microk8s.kubectl kubectl >/dev/null 2>&1 \
    && { ok "aliased kubectl -> microk8s.kubectl"; CHANGED+=("kubectl alias"); } \
    || warn "could not create the kubectl alias; use 'microk8s kubectl' instead"
else
  warn "no kubectl and no microk8s found"
fi

# ------------------------------------------------------------------- 3. Trivy

head2 "Trivy"

if command -v trivy >/dev/null 2>&1; then
  ok "already installed: $(trivy --version 2>/dev/null | head -1)"
else
  install -m 0755 -d /usr/share/keyrings
  if curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
       | gpg --dearmor --yes -o /usr/share/keyrings/trivy.gpg 2>/dev/null; then
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg arch=$ARCH_DEB] https://aquasecurity.github.io/trivy-repo/deb generic main" \
      > /etc/apt/sources.list.d/trivy.list
    apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq trivy >/dev/null 2>&1
  fi
  if ! command -v trivy >/dev/null 2>&1; then
    warn "apt route failed; falling back to the install script"
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin >/dev/null 2>&1
  fi
  if command -v trivy >/dev/null 2>&1; then
    ok "installed: $(trivy --version 2>/dev/null | head -1)"
    CHANGED+=("trivy")
  else
    err "trivy could not be installed"
  fi
fi

# The DB is ~700MB and downloading it as root would leave a root-owned cache that the
# normal user cannot write, so it is fetched as the target user instead.
if command -v trivy >/dev/null 2>&1; then
  say "  warming the vulnerability database as $TARGET_USER (a few minutes)..."
  sudo -u "$TARGET_USER" -H trivy image --download-db-only >/dev/null 2>&1 \
    && ok "vulnerability DB downloaded into $TARGET_HOME/.cache" \
    || warn "DB download failed; the first scan will retry"
fi

# -------------------------------------------------------------------- 4. Helm

head2 "Helm"

if command -v helm >/dev/null 2>&1; then
  ok "already installed: $(helm version --short 2>/dev/null)"
elif command -v microk8s >/dev/null 2>&1; then
  # MicroK8s ships helm3 as an addon, which keeps it consistent with the cluster.
  microk8s enable helm3 >/dev/null 2>&1 \
    && snap alias microk8s.helm3 helm >/dev/null 2>&1 \
    && { ok "enabled microk8s helm3 and aliased it to helm"; CHANGED+=("helm"); } \
    || warn "could not enable the microk8s helm3 addon"
else
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \
    | bash >/dev/null 2>&1 && { ok "helm installed"; CHANGED+=("helm"); } \
    || warn "helm install failed"
fi

# ---------------------------------------------------------------- 5. the report

head2 "What changed"

if [ ${#CHANGED[@]} -eq 0 ]; then
  say "  nothing - everything was already in place"
else
  for c in "${CHANGED[@]}"; do say "  * $c"; done
fi

head2 "Untouched, deliberately"
say "  * the running MicroK8s cluster, its addons and its workloads"
say "  * every other user's files and sessions"
say "  * Falco - install it separately once the box owner agrees:"
say "        bash scripts/falco_setup.sh install"

head2 "Next"
say "  Group membership only applies to NEW logins. Either:"
say "      exit and reconnect over SSH      (simplest)"
say "  or, in this shell only:"
say "      newgrp microk8s"
say ""
say "  Then confirm it worked:"
say "      kubectl get nodes"
say "      docker info >/dev/null && echo docker-ok"
say "      trivy --version"
say ""
