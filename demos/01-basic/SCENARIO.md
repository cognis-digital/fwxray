# Demo 01 - basic firmware OTA diff

This demo ships two tiny synthetic firmware images and shows how FWXRAY
turns a binary OTA into a human-readable changelog.

## Files

- `make_images.py` - regenerates `old.bin` and `new.bin` deterministically
  (already generated and committed alongside this scenario).
- `old.bin` - baseline image: a small header, a config block with flags,
  a gzip-magic payload, and a low-entropy padding tail.
- `new.bin` - the "after OTA" image with realistic changes:
  - `debug` flag flipped `0` -> `1`
  - `fw_version` bumped `1.2.3` -> `1.3.0`
  - a new `feature_x` flag added
  - the padding tail replaced with high-entropy (pseudo-random) bytes,
    simulating a newly encrypted/compressed region (entropy shift).

## Run it

```
python -m fwxray diff demos/01-basic/old.bin demos/01-basic/new.bin
python -m fwxray diff demos/01-basic/old.bin demos/01-basic/new.bin --format json
```

## Expected result

- Exit code **1** (the images differ, so a CI gate would fire).
- `flags_flipped` reports `debug` and `fw_version` changing.
- `flags_added` reports `feature_x`.
- `entropy_shifts` reports the padding-tail region jumping toward ~8 bits/byte.
- `strings_added` / `strings_removed` reflect the changed config text.

Regenerate the inputs with:

```
python demos/01-basic/make_images.py
```
