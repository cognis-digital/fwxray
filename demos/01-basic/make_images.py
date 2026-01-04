"""Generate deterministic demo firmware images for FWXRAY demo 01.

Standard library only. Produces old.bin and new.bin next to this script.
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))


def build(version: str, debug: str, extra_flags: str, hi_entropy_tail: bool) -> bytes:
    header = b"FWHDR\x01\x00\x00"  # fake header
    config = (
        b"\n".join(
            [
                b"fw_version=" + version.encode(),
                b"debug=" + debug.encode(),
                b"region=us",
                b"vendor=AcmeIoT",
                extra_flags.encode(),
            ]
        )
        + b"\n"
    )
    # gzip magic + filler to look like a compressed payload section.
    payload = b"\x1f\x8b\x08\x00" + bytes(range(256)) * 4
    if hi_entropy_tail:
        rng = random.Random(1337)
        tail = bytes(rng.randrange(256) for _ in range(2048))
    else:
        tail = b"\x00" * 2048
    return header + config + payload + tail


def main() -> None:
    old = build("1.2.3", "0", "telemetry=on", hi_entropy_tail=False)
    new = build("1.3.0", "1", "telemetry=on\nfeature_x=enabled", hi_entropy_tail=True)
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin (%d bytes) and new.bin (%d bytes)" % (len(old), len(new)))


if __name__ == "__main__":
    main()
