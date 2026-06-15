"""RUGRADAR MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from rugradar.core import scan_text


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-rugradar[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-rugradar[mcp]'",
            file=sys.stderr,
        )
        return 1

    app = FastMCP("rugradar")

    @app.tool()
    def rugradar_scan(target: str) -> str:
        """Token contract risk scanner detecting honeypots, hidden mint/blacklist,
        owner backdoors and fee traps. Returns JSON findings."""
        try:
            report = scan_text(target)
        except (ValueError, TypeError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(report, indent=2)

    app.run()
    return 0
