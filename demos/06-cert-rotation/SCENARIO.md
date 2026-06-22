# Demo 06 - benign TLS CA rotation (expected change, negative control)

A smart-meter vendor (GridSense) publishes the rotation of its pinned root CA
ahead of expiry. An analyst diffs the images to confirm the change matches the
published rotation notice and that *nothing else* moved.

## Where the data came from

- `old.bin` - image `3.0.7` with the outgoing CA bundle.
- `new.bin` - image with the rotated CA plus a `ca_rotation=2026-Q2` marker.

The embedded PEM blocks are **obviously-synthetic placeholders** (deterministic
hex filler, not real certificates or keys). fwxray diffs bytes, so no real cert
material is needed - and none should ever be fabricated.

## Run it

```bash
python -m fwxray diff demos/06-cert-rotation/old.bin demos/06-cert-rotation/new.bin
python -m fwxray diff demos/06-cert-rotation/old.bin demos/06-cert-rotation/new.bin --format json
```

## What to expect

- Exit code **1** (images differ - a diff is expected here).
- The PEM/certificate region changes content (visible in the section + string
  deltas) while the rest of the config stays put.
- `flags_added` shows the single expected `ca_rotation` marker.
- **No** unexpected flag flips, no new endpoints, no entropy anomalies.

## How to act

This is the "good" case: the only changes are the CA swap and its dated marker,
exactly matching the rotation notice. Approve the rollout. Use this demo as a
negative control when tuning a CI gate so you don't flag legitimate rotations.

Regenerate inputs with `python demos/06-cert-rotation/make_images.py`.
