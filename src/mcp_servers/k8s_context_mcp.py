"""
MCP server: k8s-context — Kubernetes deployment context (cluster-optional).

Run: python3 -m src.mcp_servers.k8s_context_mcp
"""

from mcp.server.fastmcp import FastMCP

from src.context.k8s_context import get_context

mcp = FastMCP("k8s-context")


@mcp.tool()
def pod_context(image: str) -> dict:
    """Deployment context for an image: deployed? exposed? namespace? privileged?

    Returns {"available": False} if no cluster is reachable.
    """
    return get_context(image)


@mcp.tool()
def is_exposed(image: str) -> dict:
    """Quick check: is an image running behind an internet-facing service?"""
    ctx = get_context(image)
    return {
        "image": image,
        "available": ctx.get("available", False),
        "exposed": ctx.get("exposed", False),
        "exposure_type": ctx.get("exposure_type"),
    }


if __name__ == "__main__":
    mcp.run()
