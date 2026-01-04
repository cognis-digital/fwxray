"""FWXRAY MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from fwxray.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-fwxray[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-fwxray[mcp]'")
        return 1
    app = FastMCP("fwxray")

    @app.tool()
    def fwxray_scan(target: str) -> str:
        """Diff two firmware images and surface exactly what changed: new binaries, flipped config flags, added certs, and shifted entropy regions.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
