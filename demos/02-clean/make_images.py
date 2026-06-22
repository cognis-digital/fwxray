"""Generate demo images for FWXRAY demo 02 - clean baseline (no findings).

Standard library only. Deterministic. Writes two identical images so the diff
yields zero findings and exit code 0 - the canonical "clean" case.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build() -> bytes:
    header = b"FWHDR\x01\x00\x00"
    config = b"\n".join([
        b"fw_version=1.0.0",
        b"vendor=AcmeIoT",
        b"region=us",
        b"debug=0",
    ]) + b"\n"
    payload = b"\x1f\x8b\x08\x00" + bytes(range(128)) * 4
    tail = b"\x00" * 1024
    return header + config + payload + tail


def main() -> None:
    img = build()
    for name in ("old.bin", "new.bin"):
        with open(os.path.join(HERE, name), "wb") as f:
            f.write(img)
    print("wrote old.bin/new.bin (%d bytes each, identical)" % len(img))


if __name__ == "__main__":
    main()
