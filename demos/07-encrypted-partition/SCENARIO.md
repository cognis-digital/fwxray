# Demo 07 - rootfs switched to an encrypted blob (entropy spike)

A vendor (Helio) moves its application partition from a plaintext/compressed
layout to an encrypted one between `4.2.0` and `4.3.0`. This hardens the device
but also blinds downstream SBOM/CVE tooling, so a security team wants the change
called out explicitly rather than discovered later.

## Where the data came from

- `old.bin` - `4.2.0`, with a compressible plaintext application region.
- `new.bin` - `4.3.0`, with that region replaced by a high-entropy blob.

(Synthetic, deterministic via `make_images.py`. The "ciphertext" is a seeded
pseudo-random stand-in - no real keys involved.)

## Run it

```bash
python -m fwxray diff demos/07-encrypted-partition/old.bin demos/07-encrypted-partition/new.bin
python -m fwxray diff demos/07-encrypted-partition/old.bin demos/07-encrypted-partition/new.bin \
  --block 1024 --entropy-threshold 1.0
```

## What to expect

- Exit code **1** (images differ).
- `entropy_shifts` reports several blocks jumping toward ~8 bits/byte - the
  fingerprint of a region that became encrypted/random.
- `flags_flipped` shows `rootfs: squashfs -> luks-aes256`.
- A large batch of plaintext strings disappears (`strings_removed`).

## How to act

Confirm the encryption switch is intentional and documented. If it is, update
your SBOM/CVE pipeline to consume the build-time manifest instead of unpacking
the now-opaque partition. If it is **not** expected, treat a sudden
high-entropy region as a red flag (packed/encrypted payload) and investigate.

Regenerate inputs with `python demos/07-encrypted-partition/make_images.py`.
