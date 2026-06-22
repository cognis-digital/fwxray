# Demo 10 - legitimate feature update grows the rootfs

A device vendor (Aria) ships `1.4.0`, a real feature release that adds a VPN
daemon and several new busybox applets. The squashfs root filesystem grows and
new userland strings appear. An analyst diffs it to confirm the growth matches
the feature changelog and introduces nothing unexpected.

## Where the data came from

- `old.bin` - `1.3.0` with a baseline busybox applet set.
- `new.bin` - `1.4.0` adding `wget`, `nslookup`, `crond`, `udhcpc` and a
  `wireguard-go` daemon.

(Synthetic, deterministic via `make_images.py`. Standard library only.)

## Run it

```bash
python -m fwxray diff demos/10-squashfs-grow/old.bin demos/10-squashfs-grow/new.bin
python -m fwxray diff demos/10-squashfs-grow/old.bin demos/10-squashfs-grow/new.bin --format json
```

## What to expect

- Exit code **1** (images differ).
- `sections_changed` shows the `squashfs(le)` section growing (positive
  `size_delta`).
- `strings_added` lists the new applet/daemon paths
  (`/bin/wget`, `/usr/sbin/wireguard-go`, ...).
- `flags_flipped` shows the expected `fw_version: 1.3.0 -> 1.4.0`.

## How to act

Cross-check the added binaries against the published changelog. New network
tools (`wget`, `wireguard-go`) expand the attack surface, so confirm each is
intended and update firewall/SBOM baselines accordingly. If an applet appears
that isn't in the changelog, treat it as an unexplained addition and escalate.

Regenerate inputs with `python demos/10-squashfs-grow/make_images.py`.
