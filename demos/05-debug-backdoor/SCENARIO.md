# Demo 05 - release candidate ships with debug services left on

An industrial gateway vendor (Meridian-OT) cuts a release candidate
(`5.1.0-rc2`). A pre-ship security review diffs the RC against the last shipped
build to make sure no developer debug affordances leaked into the artifact.

## Where the data came from

- `old.bin` - the shipped `5.1.0` production image (telnet off, no root SSH).
- `new.bin` - the `5.1.0-rc2` candidate straight off the build server.

(Synthetic, deterministic via `make_images.py`. Standard library only.)

## Run it

```bash
python -m fwxray diff demos/05-debug-backdoor/old.bin demos/05-debug-backdoor/new.bin
python -m fwxray diff demos/05-debug-backdoor/old.bin demos/05-debug-backdoor/new.bin --format sarif
```

## What to expect

- Exit code **1** (images differ).
- `flags_flipped` lights up across the board:
  - `telnetd: disabled -> enabled`
  - `ssh_root_login: no -> yes`
  - `console: secure -> root`
  - `log_level: warn -> debug`
- `flags_added` shows a dropped-in `debug_shell=/bin/sh`.

## How to act

This is a classic debug-services-left-on regression. **Do not promote this RC.**
Send it back to engineering to strip telnet, disable root SSH/console, restore
the production log level, and remove the debug shell. The SARIF output drops
straight into a code-scanning gate so the pipeline fails automatically.

Regenerate inputs with `python demos/05-debug-backdoor/make_images.py`.
