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
    "You are a Kubernetes DevSecOps assistant with tools to scan images, look up "
    "EPSS scores, check the CISA KEV catalog, classify CVEs with SSVC, query the "
    "CVE intelligence database, inspect Kubernetes context, and read/generate "
    "triage reports.\n\n"
    "How to work:\n"
    "- Be decisive. Call each tool AT MOST ONCE per CVE, then STOP and write the "
    "answer. Never repeat a tool call you already made.\n"
    "- To explain a CVE, the epss, kev and ssvc tools are usually enough. As soon "
    "as you have that data, give the final answer — do not keep calling tools.\n"
    "- You cannot browse the filesystem. Only use read_report if you were given an "
    "exact file path. If read_report returns '[not found]', do NOT guess other "
    "paths — just answer from the CVE-lookup tools using the CVE ID.\n"
    "- Ignore stray text such as a pasted filename; extract the CVE ID and answer.\n"
    "- Be concise and actionable. When you call a CVE urgent, say why (EPSS, KEV, "
    "exploit, exposure)."
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


def _message_text(message) -> str:
    """Extract plain text from an LLM message whose `content` may be a string or a
    list of content blocks. Gemini returns blocks like
    {'type': 'text', 'text': ..., 'extras': {'signature': ...}}; printing the raw
    list dumps the block repr (and the opaque thought signature), so pull the text.
    """
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(block.get("text") or block.get("content") or "")
            else:
                parts.append(str(block))
        return "".join(parts).strip()
    return str(content)


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
            # recursion_limit caps runaway tool loops (a flailing model would
            # otherwise call tools until langgraph's default ~25-step limit).
            result = await agent.ainvoke(
                {"messages": history},
                config={"recursion_limit": 15},
            )
            messages = result["messages"]
            answer = messages[-1]
            print(f"\nbot> {_message_text(answer)}")
            history = messages  # keep full context (incl. tool calls)
        except Exception as e:
            if "recursion" in str(e).lower():
                print("[!] The assistant kept calling tools without converging. "
                      "Try rephrasing (just the CVE ID), or set a stronger model, "
                      "e.g. LLM_MODEL=gemini-2.5-pro.")
            else:
                print(f"[!] Error: {e}")


def run_chat() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    run_chat()
