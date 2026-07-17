"""
Kubernetes deployment-context extractor (P3) — cluster-optional.

If the `kubernetes` package is missing or no cluster is reachable, everything
degrades to {"available": False} and triage proceeds unchanged.
"""


# ---------------------------------------------------------------------------
# Pure helpers (no kubernetes dependency)
# ---------------------------------------------------------------------------

def normalize_image(name: str) -> str:
    """
    Reduce an image reference to 'repo/path:tag' for comparison, dropping the
    registry host and any digest.
    """
    if not name:
        return ""
    ref = name.split("@", 1)[0]  # drop digest
    first = ref.split("/", 1)[0]
    # strip a registry host (contains a dot or a port, or is 'localhost')
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        ref = ref.split("/", 1)[1]
    # collapse docker library namespace
    if ref.startswith("library/"):
        ref = ref[len("library/"):]
    return ref


def images_match(scanned: str, pod_image: str) -> bool:
    """True if a scanned image ref and a pod's image ref refer to the same image."""
    a, b = normalize_image(scanned), normalize_image(pod_image)
    if not a or not b:
        return False
    if a == b:
        return True
    # tag-insensitive fallback: same repo path
    return a.split(":", 1)[0] == b.split(":", 1)[0]


def _selector_matches(selector: dict, labels: dict) -> bool:
    """A service selects a pod if every selector key/value is in the pod labels."""
    if not selector:
        return False
    return all(labels.get(k) == v for k, v in selector.items())


def derive_context(
    image: str,
    pods: list[dict],
    services: list[dict],
    ingresses: list[dict],
    admin_service_accounts: frozenset = frozenset(),
) -> dict:
    """
    Build the context dict from already-fetched, plain-dict cluster objects.

    pods:      [{namespace, name, labels{}, images[], privileged, host_network, service_account}]
    services:  [{namespace, type, selector{}}]
    ingresses: [{namespace, service_names[]}]
    """
    matching = [p for p in pods if any(images_match(image, img) for img in p.get("images", []))]
    if not matching:
        return {"available": True, "deployed": False, "image": image}

    namespaces = sorted({p["namespace"] for p in matching})
    privileged = any(p.get("privileged") or p.get("host_network") for p in matching)
    sa_privileged = any(
        p.get("service_account", "default") in admin_service_accounts for p in matching
    )

    exposed = False
    exposure_type = None
    exposing_service_names: set[str] = set()

    for pod in matching:
        for svc in services:
            if svc["namespace"] != pod["namespace"]:
                continue
            if _selector_matches(svc.get("selector", {}), pod.get("labels", {})):
                exposing_service_names.add(svc.get("name", ""))
                if svc.get("type") in ("LoadBalancer", "NodePort"):
                    exposed = True
                    exposure_type = svc.get("type")

    # Ingress in front of a matching service also counts as exposed
    if not exposed:
        for ing in ingresses:
            if ing["namespace"] in namespaces and (
                exposing_service_names & set(ing.get("service_names", []))
            ):
                exposed = True
                exposure_type = "Ingress"
                break

    return {
        "available": True,
        "deployed": True,
        "image": image,
        "namespaces": namespaces,
        "exposed": exposed,
        "exposure_type": exposure_type,
        "privileged": privileged,
        "sa_privileged": sa_privileged,
    }


# ---------------------------------------------------------------------------
# Live cluster access (kubernetes package)
# ---------------------------------------------------------------------------

def _load_cluster():
    """Load kube config (in-cluster first, then kubeconfig). Returns the k8s client module or None."""
    try:
        from kubernetes import client, config as kube_config
    except Exception:
        print("[*] kubernetes package not installed — skipping K8s context")
        return None
    try:
        kube_config.load_incluster_config()
    except Exception:
        try:
            kube_config.load_kube_config()
        except Exception:
            print("[*] No reachable Kubernetes cluster — skipping K8s context")
            return None
    return client


def _fetch_cluster_objects(client) -> tuple[list, list, list, frozenset]:
    """Pull pods, services, ingresses, and cluster-admin service accounts as plain dicts."""
    core = client.CoreV1Api()
    pods = []
    for p in core.list_pod_for_all_namespaces().items:
        spec = p.spec
        containers = spec.containers or []
        privileged = any(
            (c.security_context and c.security_context.privileged) for c in containers
        )
        pods.append({
            "namespace": p.metadata.namespace,
            "name": p.metadata.name,
            "labels": p.metadata.labels or {},
            "images": [c.image for c in containers if c.image],
            "privileged": bool(privileged),
            "host_network": bool(spec.host_network),
            "service_account": spec.service_account_name or "default",
        })

    services = []
    for s in core.list_service_for_all_namespaces().items:
        services.append({
            "namespace": s.metadata.namespace,
            "name": s.metadata.name,
            "type": s.spec.type,
            "selector": s.spec.selector or {},
        })

    ingresses = []
    try:
        net = client.NetworkingV1Api()
        for ing in net.list_ingress_for_all_namespaces().items:
            names = []
            for rule in (ing.spec.rules or []):
                if rule.http:
                    for path in (rule.http.paths or []):
                        if path.backend and path.backend.service:
                            names.append(path.backend.service.name)
            ingresses.append({"namespace": ing.metadata.namespace, "service_names": names})
    except Exception:
        pass

    admin_sas: set[str] = set()
    try:
        rbac = client.RbacAuthorizationV1Api()
        for crb in rbac.list_cluster_role_binding().items:
            if crb.role_ref and crb.role_ref.name == "cluster-admin":
                for subj in (crb.subjects or []):
                    if subj.kind == "ServiceAccount":
                        admin_sas.add(subj.name)
    except Exception:
        pass

    return pods, services, ingresses, frozenset(admin_sas)


def get_context(image: str) -> dict:
    """Fetch live deployment context for an image. {'available': False} if no cluster."""
    client = _load_cluster()
    if client is None:
        return {"available": False}
    try:
        pods, services, ingresses, admin_sas = _fetch_cluster_objects(client)
    except Exception as e:
        print(f"[*] Could not read cluster objects ({e}) — skipping K8s context")
        return {"available": False}

    ctx = derive_context(image, pods, services, ingresses, admin_sas)
    if ctx.get("deployed"):
        exp = ctx.get("exposure_type") or "internal-only"
        print(f"[+] K8s context: {image} deployed in {ctx['namespaces']} ({exp})")
    else:
        print(f"[+] K8s context: {image} not deployed in the cluster")
    return ctx


def make_context_provider(image: str):
    """
    Return a callable(cve)->context dict for use by the triage agent.
    """
    context = get_context(image)

    def provider(_cve: dict) -> dict:
        return context

    return provider
