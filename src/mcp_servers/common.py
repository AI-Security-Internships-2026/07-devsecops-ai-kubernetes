"""
Shared helpers for the MCP servers.

Importable without the `mcp` package (the servers import FastMCP themselves).
"""


def to_jsonable(obj):
    """Recursively convert sets/tuples (and leave dict/list/scalars) JSON-safe."""
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    return obj


_KEV_CACHE: dict = {}


def kev_ids() -> set[str]:
    """Cached CISA KEV id set (fetched once per process)."""
    if "ids" not in _KEV_CACHE:
        from src.enrichment.kev_client import fetch_kev_ids
        _KEV_CACHE["ids"] = fetch_kev_ids()
    return _KEV_CACHE["ids"]
