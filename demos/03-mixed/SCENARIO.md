# Demo 03 - mixed real-world point release

A typical `2.1.0 -> 2.1.1` point release: mostly benign (version bump, a new
compressed UI asset) with one item worth a second look (a tail region whose
entropy rises). Demonstrates fwxray reporting across all four axes at once.

## Where the data came from

- `old.bin` - the `2.1.0` image.
- `new.bin` - the `2.1.1` OTA payload.

(Synthetic, deterministic via `make_images.py`. Standard library only.)

## Run it

```bash
python -m fwxray diff demos/03-mixed/old.bin demos/03-mixed/new.bin
python -m fwxray diff demos/03-mixed/old.bin demos/03-mixed/new.bin --format json
```

## What to expect

- Exit code **1** (images differ).
- `flags_flipped` shows the `fw_version` bump.
- A new `zip`-magic asset section appears (the UI bundle).
- `entropy_shifts` reports the tail region rising toward high entropy.
- `strings_added` includes the new asset name.

## How to act

The version bump and UI asset are expected. The entropy rise in the tail is the
one thing to confirm against the changelog - if it's a newly compressed asset,
fine; if it's unexplained, investigate before rollout.

Regenerate inputs with `python demos/03-mixed/make_images.py`.
