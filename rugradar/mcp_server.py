"""RUGRADAR MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from rugradar.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-rugradar[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-rugradar[mcp]'")
        return 1
    app = FastMCP("rugradar")

    @app.tool()
    def rugradar_scan(target: str) -> str:
        """Token contract risk scanner detecting honeypots, hidden mint/blacklist functions, owner backdoors, and unlocked liquidity before you ape.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
