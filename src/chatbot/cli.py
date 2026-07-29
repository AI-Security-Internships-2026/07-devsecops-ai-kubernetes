"""
Interactive CLI chatbot.

A terminal REPL where you can ask about your scans in natural language. It
connects to the project's MCP servers (scanner, epss, ssvc, kev, cvedb,
k8s-context, report) and lets an LLM call them as tools to answer.

    python run.py chat

Backend LLM: Groq or Google Gemini — set GROQ_API_KEY or GOOGLE_API_KEY.
Must be run from the repo root (the MCP servers import the `src` package).

Example questions:
    - "scan redis:7 and summarise the findings"
    - "why would CVE-2023-45288 be critical?"
    - "which of my images are affected by CVE-2024-3094?"
    - "any fresh CVE alerts?"
"""

import asyncio
import json

from dotenv import load_dotenv

from src import config
from src.triage.explain import get_llm

SYSTEM_PROMPT = (
    "You are a Kubernetes DevSecOps assistant. You have tools to scan images, "
    "look up EPSS scores, check the CISA KEV catalog, classify CVEs with SSVC, "
    "query the CVE intelligence database, inspect Kubernetes context, and run "
    "triage reports. Use tools when they help; be concise and actionable. When "
    "you state a CVE is urgent, say why (EPSS, KEV, exploit, exposure)."
)


def load_server_config() -> dict:
    """Read .mcp.json and shape it for langchain-mcp-adapters (stdio transport)."""
    data = json.loads((config.ROOT / ".mcp.json").read_text(encoding="utf-8"))
    servers = {}
    for name, cfg in data.get("mcpServers", {}).items():
        servers[name] = {
            "command": cfg["command"],
            "args": cfg["args"],
            "transport": "stdio",
        }
    return servers


async def _amain() -> None:
    load_dotenv()
    llm = get_llm()
    if llm is None:
        print("[!] No LLM configured. Set GROQ_API_KEY or GOOGLE_API_KEY in .env.")
        return

    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient
        from langgraph.prebuilt import create_react_agent
        from langchain_core.messages import SystemMessage, HumanMessage
    except Exception as e:
        print(f"[!] Missing dependency: {e}")
        print("[!] pip install langchain-mcp-adapters langgraph")
        return

    servers = load_server_config()
    print(f"[*] Connecting to {len(servers)} MCP servers: {', '.join(servers)}")
    client = MultiServerMCPClient(servers)
    tools = await client.get_tools()
    print(f"[+] Loaded {len(tools)} tools from MCP servers")

    agent = create_react_agent(llm, tools)

    print("\n" + "=" * 66)
    print(" DevSecOps AI Assistant — ask about your scans. 'exit' to quit.")
    print("=" * 66)

    history = [SystemMessage(content=SYSTEM_PROMPT)]
    while True:
        try:
            user = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if user.lower() in ("exit", "quit"):
            break
        if not user:
            continue

        history.append(HumanMessage(content=user))
        try:
            result = await agent.ainvoke({"messages": history})
            messages = result["messages"]
            answer = messages[-1]
            content = getattr(answer, "content", str(answer))
            print(f"\nbot> {content}")
            history = messages  # keep full context (incl. tool calls)
        except Exception as e:
            print(f"[!] Error: {e}")


def run_chat() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    run_chat()
