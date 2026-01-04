# FWXRAY — Architecture

> Diff two firmware images and surface exactly what changed: new binaries, flipped config flags, added certs, and shifted entropy regions.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `fwxray/core.py`.
- **score** ranks by severity.
- **MCP server** (`fwxray mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
