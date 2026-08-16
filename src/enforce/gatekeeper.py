"""
OPA Gatekeeper policy generation.

Turns triage findings into ready-to-apply Gatekeeper policies, closing the loop
from *decide* toward *enforce*:  scan -> decide -> (generate) enforce.

This week we only GENERATE the YAML; a human reviews and `kubectl apply`s it.
Live admission enforcement (installing Gatekeeper, blocking bad deploys) is the
follow-up.

Generates three policies from a triage report:
  1. Block the specific image(s) that have Act-level (CRITICAL) findings.
  2. Require pinned image digests (no mutable ':latest' tags).
  3. Deny privileged containers.

Usage:
    python run.py gatekeeper experiments/results/triage_run_<image>.json
"""

import json
import re
import sys
from pathlib import Path

from src import config

# Anything outside the legal OCI image-reference charset is stripped before an
# image name is interpolated into generated YAML/Rego.
_IMAGE_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._:/@-]")
# Only well-formed CVE IDs are allowed into generated policy text.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def sanitize_image(image: str) -> str:
    """
    Reduce an image reference to the legal OCI charset (alphanumerics plus
    `. _ - : / @`), truncated to a sane length.

    Image names originate from scan data, which is attacker-influenced in a real
    supply-chain scenario, and they get interpolated into the YAML/Rego we emit.
    Stripping quotes, newlines and braces here means a hostile image name cannot
    escape its string context and inject policy content.
    """
    return _IMAGE_UNSAFE_RE.sub("", str(image or ""))[:255]


def safe_cve_ids(act: list[dict]) -> list[str]:
    """Keep only well-formed CVE IDs (defence in depth for generated policy text)."""
    ids = []
    for a in act:
        cve = str(a.get("cve") or "")
        if _CVE_RE.match(cve):
            ids.append(cve.upper())
    return ids


def _yaml_str(value: str) -> str:
    """
    Render a value as a YAML double-quoted scalar with correct escaping.

    JSON string syntax is a valid YAML double-quoted scalar, so json.dumps gives
    us the escaping (quotes, backslashes, control characters) for free.
    """
    return json.dumps(str(value))


def load_findings(triage_json_path: str, image_override: str | None = None) -> tuple[str, list[dict]]:
    """
    Read a triage report (triage_run.json or triage_report_*.json) and return
    (container_image, act_findings). Tolerant of both output formats.
    """
    data = json.loads(Path(triage_json_path).read_text(encoding="utf-8"))
    findings = data.get("findings", [])

    image = image_override or data.get("container_image")
    if not image:
        # fall back to the source filename
        stem = Path(data.get("source_file", triage_json_path)).stem
        image = stem.replace("epss_enriched_trivy_", "").replace("triage_run_", "")

    act = []
    for f in findings:
        priority = (f.get("priority") or "").upper()
        if priority == "CRITICAL":
            act.append({
                "cve": f.get("cve_id") or f.get("cve"),
                "epss": f.get("epss_score", 0.0),
                "kev": f.get("kev_status", f.get("in_kev", False)),
            })
    return image, act


def _block_images_policy(image: str, act: list[dict]) -> str:
    """ConstraintTemplate + Constraint: deny pods using a blocked (vulnerable) image.

    `image` is sanitized and YAML-quoted, and only well-formed CVE IDs reach the
    Rego message, so neither can break out of its string context.
    """
    image = sanitize_image(image)
    cve_list = ", ".join(safe_cve_ids(act)[:10]) or "Act-level findings"
    return f"""apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockvulnerableimages
  annotations:
    description: >-
      Deny pods that use an image flagged with Act-level (CRITICAL) findings by
      the DevSecOps AI triage tool. Generated from a triage run.
spec:
  crd:
    spec:
      names:
        kind: K8sBlockVulnerableImages
      validation:
        openAPIV3Schema:
          type: object
          properties:
            blockedImages:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockvulnerableimages
        violation[{{"msg": msg}}] {{
          container := input.review.object.spec.containers[_]
          blocked := input.parameters.blockedImages[_]
          container.image == blocked
          msg := sprintf("image %v is blocked: Act-level CVEs found by triage ({cve_list})", [container.image])
        }}
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockVulnerableImages
metadata:
  name: block-vulnerable-images
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    blockedImages:
      - {_yaml_str(image)}
"""


def _require_digest_policy() -> str:
    return """apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequireimagedigest
  annotations:
    description: >-
      Require images to be pinned by digest (@sha256:...) rather than a mutable
      tag such as ':latest', so a scanned+approved image cannot silently change.
spec:
  crd:
    spec:
      names:
        kind: K8sRequireImageDigest
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequireimagedigest
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not contains(container.image, "@sha256:")
          msg := sprintf("image %v must be pinned by digest (@sha256:...)", [container.image])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireImageDigest
metadata:
  name: require-image-digest
spec:
  enforcementAction: dryrun
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
"""


def _deny_privileged_policy() -> str:
    return """apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdenyprivileged
  annotations:
    description: >-
      Deny privileged containers (privileged: true) — a privileged container can
      escape to the host, which is exactly the blast radius our K8s-context layer
      escalates on.
spec:
  crd:
    spec:
      names:
        kind: K8sDenyPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdenyprivileged
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := sprintf("privileged container %v is not allowed", [container.name])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDenyPrivileged
metadata:
  name: deny-privileged
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
"""


def generate_policies(image: str, act: list[dict]) -> str:
    """Return the full multi-document Gatekeeper YAML for a triage result."""
    # Sanitize once here too, so a newline/quote in the image name can't forge
    # extra YAML through the header comment either.
    image = sanitize_image(image)
    header = (
        f"# OPA Gatekeeper policies generated by DevSecOps AI triage\n"
        f"# Image: {image}\n"
        f"# Act-level (CRITICAL) CVEs: {len(act)}\n"
        f"# NOTE: generated suggestions — review before `kubectl apply`.\n"
    )
    docs = [header, _block_images_policy(image, act),
            _require_digest_policy(), _deny_privileged_policy()]
    return "\n---\n".join(docs)


def run(triage_json_path: str, image_override: str | None = None) -> Path:
    """Generate Gatekeeper YAML from a triage report and save it."""
    image, act = load_findings(triage_json_path, image_override)
    yaml_text = generate_policies(image, act)

    config.ensure_dirs()
    safe = sanitize_image(image).replace("/", "_").replace(":", "_").replace("@", "_")
    out_path = config.RESULTS_DIR / f"gatekeeper_{safe}.yaml"
    out_path.write_text(yaml_text, encoding="utf-8")
    print(f"[+] Gatekeeper policies for {image} ({len(act)} Act CVEs) -> {out_path}")
    print("[*] Review, then: kubectl apply --dry-run=client -f " + str(out_path))
    return out_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py gatekeeper <triage_json> [--image NAME]")
        sys.exit(1)
    image_override = None
    if "--image" in sys.argv:
        image_override = sys.argv[sys.argv.index("--image") + 1]
    run(sys.argv[1], image_override)


if __name__ == "__main__":
    main()
