"""
Explanation layer for triage findings.

Kept separate from the LangGraph orchestration so the deterministic
`static_explanation` is importable/testable without langgraph, and the LLM
providers are imported lazily (only when an API key is actually configured).
"""

import json
import os


def _local_llm():
    """
    A self-hosted model behind an OpenAI-compatible endpoint (Ollama, vLLM, SGLang,
    LiteLLM). Reached through the OpenAI protocol rather than a vendor SDK, so the
    same code path serves any of them — and swapping the backend is an env change.

    This is the provider that lets us say vulnerability data never leaves the
    cluster's own infrastructure: no third-party API sees a CVE, an image name, or
    a namespace.
    """
    base_url = os.getenv("LOCAL_LLM_BASE_URL")
    if not base_url:
        return None
    model = os.getenv("LOCAL_LLM_MODEL", "qwen2.5-coder:32b")
    print(f"[*] Using local LLM ({model} @ {base_url}) — no data leaves this host")
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(
        model=model,
        temperature=0.2,
        base_url=base_url,
        # Local servers ignore the key but the OpenAI client requires a non-empty
        # value, so this is a placeholder, not a credential.
        api_key=os.getenv("LOCAL_LLM_API_KEY", "not-needed"),
    )


def _groq_llm():
    key = os.getenv("GROQ_API_KEY")
    if not key:
        return None
    model = os.getenv("LLM_MODEL", "llama-3.1-8b-instant")
    print(f"[*] Using Groq ({model})")
    from langchain_groq import ChatGroq
    return ChatGroq(model=model, temperature=0.2, api_key=key)


def _gemini_llm():
    key = os.getenv("GOOGLE_API_KEY")
    if not key:
        return None
    model = os.getenv("LLM_MODEL", "gemini-2.5-flash")
    print(f"[*] Using Google Gemini ({model})")
    from langchain_google_genai import ChatGoogleGenerativeAI
    return ChatGoogleGenerativeAI(model=model, temperature=0.2, google_api_key=key)


# Local first: when a self-hosted endpoint is configured it should win over any
# cloud key left in the environment, so the private path is the default path.
_PROVIDERS = {"local": _local_llm, "groq": _groq_llm, "gemini": _gemini_llm}
_PROVIDER_ORDER = ("local", "groq", "gemini")


def get_llm():
    """
    Return a configured chat model, or None if nothing is configured.

    Set LLM_PROVIDER to pin one backend (local|groq|gemini) instead of taking the
    first that happens to be configured — which is what makes an apples-to-apples
    local-vs-cloud comparison reproducible.
    """
    pinned = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    if pinned in ("none", "off", "static"):
        # Deterministic fast path: skip the model entirely and let callers fall back
        # to static_explanation. Useful for benchmarks (no model variance in the
        # numbers) and for a live demo on a contended GPU, where a few hundred
        # sequential explanation calls are the slowest part of a run.
        print("[*] LLM disabled (LLM_PROVIDER=none) - using static explanations")
        return None
    if pinned:
        factory = _PROVIDERS.get(pinned)
        if factory is None:
            print(f"[!] Unknown LLM_PROVIDER '{pinned}' "
                  f"(expected one of: {', '.join(_PROVIDERS)})")
            return None
        llm = factory()
        if llm is None:
            print(f"[!] LLM_PROVIDER='{pinned}' but it is not configured "
                  f"(missing base URL or API key)")
        return llm

    for name in _PROVIDER_ORDER:
        llm = _PROVIDERS[name]()
        if llm is not None:
            return llm
    return None


def llm_analyze_cve(llm, cve: dict, in_kev: bool) -> dict | None:
    """Generate a plain-English explanation + recommended action for one CVE."""
    from langchain_core.messages import HumanMessage, SystemMessage

    kev_note = (
        " This CVE is listed in CISA's Known Exploited Vulnerabilities catalog — "
        "confirmed active exploitation."
        if in_kev else ""
    )
    prompt = f"""You are a Kubernetes security analyst. Analyze this vulnerability and provide:
1. A plain-English risk explanation (2-3 sentences)
2. A recommended action (1 sentence)

Vulnerability details:
- CVE: {cve['cve_id']}
- Title: {cve.get('title', 'N/A')}
- Package: {cve.get('package', 'unknown')} (installed: {cve.get('installed_version', '?')}, fixed: {cve.get('fixed_version', 'N/A')})
- EPSS Score: {cve.get('epss_score', 0):.3f} ({cve.get('epss_score', 0)*100:.1f}% exploit probability in 30 days)
- CVSS: {cve.get('cvss_score', 0):.1f}
- Severity: {cve.get('severity', 'UNKNOWN')}
- CISA KEV: {'YES — actively exploited' if in_kev else 'No'}{kev_note}

Respond ONLY in this exact JSON format, no markdown fences:
{{"explanation": "your 2-3 sentence explanation here", "recommended_action": "your 1 sentence action here"}}"""

    try:
        response = llm.invoke([
            SystemMessage(content="You are a concise security analyst. Always respond in valid JSON only."),
            HumanMessage(content=prompt),
        ])
        text = response.content.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        return json.loads(text)
    except Exception:
        return None


def static_explanation(cve: dict, priority: str, in_kev: bool) -> dict:
    """Deterministic explanation when no LLM is available (pure function)."""
    epss = cve.get("epss_score", 0)
    pkg = cve.get("package", "unknown")
    fixed = cve.get("fixed_version", "")
    title = cve.get("title", "N/A")

    if priority == "CRITICAL":
        expl = (
            f"This vulnerability ({title}) in {pkg} has a {epss*100:.1f}% probability of "
            f"exploitation in the next 30 days."
        )
        if in_kev:
            expl += " Active exploitation confirmed in CISA KEV."
        action = f"Patch within 24h{' — upgrade to ' + fixed if fixed else ' or isolate container'}."
    elif priority == "HIGH":
        expl = (
            f"{title} in {pkg} has notable exploit risk (EPSS {epss:.3f}). "
            f"Combined with its severity, this warrants prompt attention."
        )
        action = f"Schedule fix this sprint{' — upgrade to ' + fixed if fixed else ''}."
    elif priority == "MEDIUM":
        expl = (
            f"{title} in {pkg} has moderate exploit probability (EPSS {epss:.3f}). "
            f"Lower impact reduces urgency but the vulnerability should be tracked."
        )
        action = "Monitor and reassess next quarter."
    else:
        expl = (
            f"{title} in {pkg} has very low exploit probability (EPSS {epss:.4f}). "
            f"Safe to defer."
        )
        action = "No immediate action required. Track for changes."

    return {"explanation": expl, "recommended_action": action}
