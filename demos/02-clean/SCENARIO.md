# Demo 02 - clean baseline (zero findings)

The canonical "nothing changed" case: two byte-for-byte identical firmware
images. Use it as a sanity check that fwxray and your CI gate stay quiet when
there is genuinely nothing to report.

## Where the data came from

- `old.bin` / `new.bin` - identical images written by `make_images.py`.

## Run it

```bash
python -m fwxray diff demos/02-clean/old.bin demos/02-clean/new.bin
echo "exit code: $?"
```

## What to expect

- Exit code **0** (no findings).
- The report prints `IDENTICAL - the two images are byte-for-byte equal.`

## How to act

Nothing to do - this is the green path. Pair it with the other demos to confirm
your gate distinguishes real changes from no-ops.

Regenerate inputs with `python demos/02-clean/make_images.py`.
