"""Generate demo images for FWXRAY demo 08 - version downgrade / rollback.

Standard library only. Deterministic. Scenario: an OTA server is tricked into
serving an OLDER signed image (a rollback / downgrade attack) to re-introduce a
patched vulnerability. The fw_version flag moves BACKWARD and a previously
removed insecure flag returns. fwxray surfaces the regression as a flag flip.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build(config_lines: list) -> bytes:
    header = b"FWHDR\x02\x00\x00\x00"
    config = b"\n".join(config_lines) + b"\n"
    rootfs = b"hsqs" + bytes(range(32)) * 24
    tail = b"\x00" * 768
    return header + config + rootfs + tail


def main() -> None:
    # "current" = patched build the device is already running.
    current = build([
        b"fw_version=7.5.2",
        b"vendor=Cobalt",
        b"sslv3_enabled=false",
        b"min_tls=1.2",
        b"cve_patchset=2026-05",
    ])
    # "served" = the OLDER image an attacker is pushing back onto the device.
    served = build([
        b"fw_version=7.4.0",          # backward: 7.5.2 -> 7.4.0
        b"vendor=Cobalt",
        b"sslv3_enabled=true",        # insecure flag returns
        b"min_tls=1.0",               # weakened
        b"cve_patchset=2026-02",      # older patch baseline
    ])
    # old.bin = what's running now; new.bin = what's being served.
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(current)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(served)
    print("wrote old.bin (%d) new.bin (%d)" % (len(current), len(served)))


if __name__ == "__main__":
    main()
