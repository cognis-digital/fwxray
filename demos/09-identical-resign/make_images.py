"""Generate demo images for FWXRAY demo 09 - byte-identical re-publish.

Standard library only. Deterministic. Scenario: an OTA channel re-publishes
what is claimed to be a "new" build, but the payload is byte-for-byte identical
to the current one (e.g. only an outer signature wrapper changed, or the CDN
re-uploaded the same artifact). fwxray confirms the images are IDENTICAL and
exits 0 - useful as a negative control and a CI no-op gate.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build() -> bytes:
    header = b"FWHDR\x02\x00\x00\x00"
    config = b"\n".join([
        b"fw_version=1.0.0",
        b"vendor=Lumen",
        b"build=release",
    ]) + b"\n"
    rootfs = b"hsqs" + bytes(range(40)) * 12
    tail = b"\x00" * 512
    return header + config + rootfs + tail


def main() -> None:
    img = build()
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(img)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(img)  # identical payload on purpose
    print("wrote old.bin (%d) new.bin (%d) [identical]" % (len(img), len(img)))


if __name__ == "__main__":
    main()
