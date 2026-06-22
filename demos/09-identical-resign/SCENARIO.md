# Demo 09 - byte-identical re-publish (no-op OTA, negative control)

An OTA channel advertises a "new" build, but the payload turns out to be
byte-for-byte identical to what's already installed (only an outer signature
wrapper changed, or the CDN simply re-uploaded the same artifact). The CI gate
should treat this as a clean no-op.

## Where the data came from

- `old.bin` - the installed image.
- `new.bin` - the "new" payload, written identically on purpose.

(Synthetic, deterministic via `make_images.py`.)

## Run it

```bash
python -m fwxray diff demos/09-identical-resign/old.bin demos/09-identical-resign/new.bin
echo "exit code: $?"
```

## What to expect

- Exit code **0** (no findings - this is the only zero-exit demo).
- The report prints `IDENTICAL - the two images are byte-for-byte equal.`
- Same SHA-256, same size, no section/flag/entropy/string deltas.

## How to act

Nothing to do. This demo exists as a negative control: it proves the gate
exits `0` and stays quiet when an "update" carries no payload change, so real
findings in the other demos aren't false positives.

Regenerate inputs with `python demos/09-identical-resign/make_images.py`.
