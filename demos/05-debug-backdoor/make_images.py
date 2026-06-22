"""Generate demo images for FWXRAY demo 05 - debug services re-enabled.

Standard library only. Deterministic. Scenario: a beta/RC firmware build for
an industrial gateway accidentally ships with developer debug services left
on - telnet, an unauthenticated root console, and a verbose log level - a
classic security regression a diff should catch before it goes to production.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build(config_lines: list) -> bytes:
    header = b"FWHDR\x02\x00\x00\x00"
    config = b"\n".join(config_lines) + b"\n"
    elf = b"\x7fELF" + bytes(range(48)) * 8   # init binary section (ELF magic)
    tail = b"\x00" * 1024
    return header + config + elf + tail


def main() -> None:
    old = build([
        b"fw_version=5.1.0",
        b"vendor=Meridian-OT",
        b"telnetd=disabled",
        b"ssh_root_login=no",
        b"console=secure",
        b"log_level=warn",
    ])
    new = build([
        b"fw_version=5.1.0-rc2",
        b"vendor=Meridian-OT",
        b"telnetd=enabled",        # flipped: debug telnet re-enabled
        b"ssh_root_login=yes",     # flipped: root SSH login allowed
        b"console=root",           # flipped: unauthenticated root console
        b"log_level=debug",        # flipped: verbose debug logging
        b"debug_shell=/bin/sh",    # added: dropped-in debug shell
    ])
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin (%d) new.bin (%d)" % (len(old), len(new)))


if __name__ == "__main__":
    main()
