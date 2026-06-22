# Demo 04 - "stability fix" OTA that silently adds telemetry

A consumer Wi-Fi router vendor (NorthGate) pushes firmware `2.4.2`, described
in the changelog only as a "stability fix." A privacy-conscious owner captures
the running image and the OTA payload and diffs them before flashing.

## Where the data came from

Two firmware images dumped from the device's update partition:

- `old.bin` - the `2.4.1` image currently installed.
- `new.bin` - the `2.4.2` OTA payload fetched from the vendor CDN.

(Synthetic, generated deterministically by `make_images.py` - standard library
only. The vendor names/endpoints are fictional placeholders.)

## Run it

```bash
python -m fwxray diff demos/04-telemetry-added/old.bin demos/04-telemetry-added/new.bin
python -m fwxray diff demos/04-telemetry-added/old.bin demos/04-telemetry-added/new.bin --format json
```

## What to expect

- Exit code **1** (images differ -> a CI privacy gate would fire).
- `flags_flipped` shows `analytics: off -> on` and
  `telemetry_optout: true -> false` - the opt-out was silently cleared.
- `flags_added` shows a new `metrics_endpoint` and `metrics_interval`.
- `strings_added` includes the new collection endpoint.

## How to act

The "stability fix" framing is misleading: the update enables analytics and
clears the user's opt-out. Hold the rollout, demand a corrected changelog, and
block the `metrics_endpoint` host at the network edge until clarified.

Regenerate inputs with `python demos/04-telemetry-added/make_images.py`.
