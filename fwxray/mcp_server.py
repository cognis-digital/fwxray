"""FWXRAY MCP server — exposes diff_firmware() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from fwxray.core import diff_firmware


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
    def fwxray_diff(old_path: str, new_path: str) -> str:
        """Diff two firmware images and surface exactly what changed: new
        binaries, flipped config flags, added certs, and shifted entropy
        regions. Returns JSON findings."""
        try:
            result = diff_firmware(old_path, new_path)
        except (OSError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(result.to_dict(), indent=2)

    app.run()
    return 0
