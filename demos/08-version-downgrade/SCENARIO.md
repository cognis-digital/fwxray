# Demo 08 - rollback / downgrade attack

An OTA distribution point is manipulated into serving an **older** signed image
to a device, re-introducing vulnerabilities that the current build had already
patched. The device-side updater diffs "what I'm running" against "what's being
served" before applying anything.

## Where the data came from

- `old.bin` - the patched `7.5.2` image the device currently runs.
- `new.bin` - the `7.4.0` image an attacker is pushing back onto the device.

(Synthetic, deterministic via `make_images.py`. Standard library only.)

## Run it

```bash
python -m fwxray diff demos/08-version-downgrade/old.bin demos/08-version-downgrade/new.bin
python -m fwxray diff demos/08-version-downgrade/old.bin demos/08-version-downgrade/new.bin --format json
```

## What to expect

- Exit code **1** (images differ).
- `flags_flipped` exposes the regression:
  - `fw_version: 7.5.2 -> 7.4.0` (version moves **backward**)
  - `sslv3_enabled: false -> true` (a disabled-for-security flag returns)
  - `min_tls: 1.2 -> 1.0`
  - `cve_patchset: 2026-05 -> 2026-02`

## How to act

A backward `fw_version` plus the return of insecure flags is the signature of a
downgrade attack. **Refuse the update.** Enforce monotonic version checks /
anti-rollback counters in the updater, and alert on the serving endpoint.

Regenerate inputs with `python demos/08-version-downgrade/make_images.py`.
