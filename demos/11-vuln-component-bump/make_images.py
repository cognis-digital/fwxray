"""Demo 11: an OTA bundles a vulnerable, actively-exploited library.

The new image ships ``log4j-core-2.14.1`` (the Log4Shell window) plus a couple
of other dated components. FWXRAY sees the new component strings; the feeds
layer maps them to OSV vulns and flags CVE-2021-44228 as CISA-KEV
known-exploited. Standard library only; deterministic.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build(components) -> bytes:
    header = b"FWHDR\x01\x00\x00"
    config = b"\n".join([b"fw_version=4.1.0", b"vendor=AcmeIoT", b"region=us"]) + b"\n"
    # squashfs-looking section whose strings name the bundled libraries.
    rootfs = b"hsqs" + b"\x00" * 16 + b"\n".join(c.encode() for c in components) + b"\n"
    payload = b"\x1f\x8b\x08\x00" + bytes(range(256)) * 4
    return header + config + rootfs + payload + b"\x00" * 1024


def main() -> None:
    old = build([
        "lib/log4j-core-2.17.1.jar",   # already patched in the baseline
        "OpenSSL 1.1.1w  11 Sep 2023",
        "BusyBox v1.36.1",
    ])
    new = build([
        "lib/log4j-core-2.14.1.jar",   # DOWNGRADE into the Log4Shell window
        "OpenSSL 1.0.2k  26 Jan 2017",  # ancient OpenSSL
        "BusyBox v1.30.1",
        "lodash 4.17.4",
    ])
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin / new.bin")


if __name__ == "__main__":
    main()
