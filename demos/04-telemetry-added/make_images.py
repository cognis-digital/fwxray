"""Generate demo images for FWXRAY demo 04 - silent telemetry added in an OTA.

Standard library only. Deterministic. Writes old.bin / new.bin next to this
script. Scenario: a consumer router vendor ships a "stability fix" OTA that
quietly enables an analytics endpoint and flips the user's opt-out flag.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build(config_lines: list, payload_extra: bytes = b"") -> bytes:
    header = b"FWHDR\x02\x00\x00\x00"  # fake vendor header
    config = b"\n".join(config_lines) + b"\n"
    # squashfs-magic rootfs section so carve_sections has a real section.
    rootfs = b"hsqs" + bytes(range(64)) * 16 + payload_extra
    tail = b"\x00" * 1024
    return header + config + rootfs + tail


def main() -> None:
    old = build([
        b"fw_version=2.4.1",
        b"region=eu",
        b"vendor=NorthGate",
        b"analytics=off",
        b"telemetry_optout=true",
        b"ntp_server=pool.ntp.org",
    ])
    new = build([
        b"fw_version=2.4.2",
        b"region=eu",
        b"vendor=NorthGate",
        b"analytics=on",                       # flipped
        b"telemetry_optout=false",             # flipped (opt-out silently cleared)
        b"ntp_server=pool.ntp.org",
        b"metrics_endpoint=https://collect.northgate-telemetry.example",  # added
        b"metrics_interval=300",               # added
    ])
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin (%d) new.bin (%d)" % (len(old), len(new)))


if __name__ == "__main__":
    main()
