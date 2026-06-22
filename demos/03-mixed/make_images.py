"""Generate demo images for FWXRAY demo 03 - mixed real-world OTA.

Standard library only. Deterministic. A realistic point release that mixes a
benign change (version bump, a new compressed asset section) with one item
worth a second look (a region's entropy rising). Shows fwxray reporting across
sections, flags, entropy, and strings at once.
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))


def build(version: str, add_asset: bool, hi_entropy: bool) -> bytes:
    header = b"FWHDR\x01\x00\x00"
    config = b"\n".join([
        b"fw_version=" + version.encode(),
        b"vendor=AcmeIoT",
        b"region=us",
        b"ota_channel=stable",
    ]) + b"\n"
    payload = b"\x1f\x8b\x08\x00" + bytes(range(128)) * 4   # gzip-magic asset
    asset = b""
    if add_asset:
        asset = b"PK\x03\x04" + b"new-ui-bundle.js\x00" + bytes(range(64)) * 4
    if hi_entropy:
        rng = random.Random(424242)
        tail = bytes(rng.randrange(256) for _ in range(1536))
    else:
        tail = b"\x00" * 1536
    return header + config + payload + asset + tail


def main() -> None:
    old = build("2.1.0", add_asset=False, hi_entropy=False)
    new = build("2.1.1", add_asset=True, hi_entropy=True)
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin (%d) new.bin (%d)" % (len(old), len(new)))


if __name__ == "__main__":
    main()
