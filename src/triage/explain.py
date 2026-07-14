"""
Explanation layer for triage findings.

Kept separate from the LangGraph orchestration so the deterministic
`static_explanation` is importable/testable without langgraph, and the LLM
providers are imported lazily (only when an API key is actually configured).
"""

import json
import os


def get_llm():
    """Return a configured chat model (Groq first, then Gemini) or None."""
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        model = os.getenv("LLM_MODEL", "llama-3.1-8b-instant")
        print(f"[*] Using Groq ({model})")
        from langchain_groq import ChatGroq
        return ChatGroq(model=model, temperature=0.2, api_key=groq_key)

    google_key = os.getenv("GOOGLE_API_KEY")
    if google_key:
        model = os.getenv("LLM_MODEL", "gemini-2.5-pro-preview-05-06")
        print(f"[*] Using Google Gemini ({model})")
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model=model, temperature=0.2, google_api_key=google_key)

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
