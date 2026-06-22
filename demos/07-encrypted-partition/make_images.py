"""Generate demo images for FWXRAY demo 07 - rootfs newly encrypted.

Standard library only. Deterministic. Scenario: between two releases a vendor
switches the application partition from a plaintext/compressed layout to an
encrypted blob. The tell-tale is a large region whose entropy jumps to ~8
bits/byte. This both hardens the device AND blocks downstream SBOM/CVE tooling,
so security teams want it flagged explicitly.
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))


def build(encrypted: bool) -> bytes:
    header = b"FWHDR\x02\x00\x00\x00"
    config = b"\n".join([
        b"fw_version=" + (b"4.2.0" if not encrypted else b"4.3.0"),
        b"vendor=Helio",
        b"rootfs=" + (b"squashfs" if not encrypted else b"luks-aes256"),
    ]) + b"\n"
    if not encrypted:
        # Low/medium entropy: repeating, compressible application data.
        region = (b"GET /api/status HTTP/1.1\r\nHost: device.local\r\n\r\n" * 200)
        region = region[:8192]
    else:
        # High entropy: deterministic pseudo-random stand-in for ciphertext.
        rng = random.Random(20260621)
        region = bytes(rng.randrange(256) for _ in range(8192))
    tail = b"\x00" * 512
    return header + config + region + tail


def main() -> None:
    old = build(encrypted=False)
    new = build(encrypted=True)
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin (%d) new.bin (%d)" % (len(old), len(new)))


if __name__ == "__main__":
    main()
