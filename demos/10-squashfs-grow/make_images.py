"""Generate demo images for FWXRAY demo 10 - feature update grows rootfs.

Standard library only. Deterministic. Scenario: a legitimate feature release
grows the squashfs root filesystem and adds new userland strings (new busybox
applets / a new daemon). fwxray reports the squashfs section changing size and
a batch of added strings - the expected signature of a real feature update.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build(applets: list, extra_daemon: bytes = b"") -> bytes:
    header = b"FWHDR\x02\x00\x00\x00"
    config = b"\n".join([
        b"fw_version=" + (b"1.4.0" if extra_daemon else b"1.3.0"),
        b"vendor=Aria",
    ]) + b"\n"
    # squashfs section whose string table carries the applet/daemon names.
    body = b"hsqs"
    for a in applets:
        body += b"/bin/" + a + b"\x00"
    body += extra_daemon
    body += bytes(range(16)) * 32  # filler so the section is sizeable
    tail = b"\x00" * 512
    return header + config + body + tail


def main() -> None:
    base_applets = [b"sh", b"ls", b"cat", b"ifconfig", b"ping"]
    old = build(base_applets)
    new = build(
        base_applets + [b"wget", b"nslookup", b"crond", b"udhcpc"],
        extra_daemon=b"/usr/sbin/wireguard-go\x00wg_iface=wg0\x00",
    )
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin (%d) new.bin (%d)" % (len(old), len(new)))


if __name__ == "__main__":
    main()
