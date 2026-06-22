"""Generate demo images for FWXRAY demo 06 - benign TLS CA cert rotation.

Standard library only. Deterministic. Scenario: a vendor rotates the pinned
root CA in a smart-meter image ahead of expiry. This is an EXPECTED change -
the point of the demo is to show fwxray cleanly surfacing a PEM section swap
so an analyst can confirm it matches the published rotation notice.

NOTE: the PEM blocks below are obviously-synthetic placeholders (deterministic
filler, not real keys/certs). fwxray works on bytes; no real cert is needed.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def _fake_pem(label: str, seed: int) -> bytes:
    # Deterministic, clearly-synthetic base64-ish body. NOT a real certificate.
    body = bytes(((seed + i) * 37) % 256 for i in range(180))
    b64 = body.hex().encode()  # hex, not real base64 - signals "synthetic"
    chunks = b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return (
        b"-----BEGIN " + label + b"-----\n" + chunks + b"\n"
        b"-----END " + label + b"-----\n"
    )


def build(ca: bytes, config_lines: list) -> bytes:
    header = b"FWHDR\x02\x00\x00\x00"
    config = b"\n".join(config_lines) + b"\n"
    certs = _fake_pem(b"CERTIFICATE", ca[0] if ca else 1) + ca
    tail = b"\x00" * 512
    return header + config + certs + tail


def main() -> None:
    old_ca = _fake_pem(b"CERTIFICATE", 11)
    new_ca = _fake_pem(b"CERTIFICATE", 200)
    cfg = [
        b"fw_version=3.0.7",
        b"vendor=GridSense",
        b"tls_min_version=1.2",
        b"ca_bundle=/etc/ssl/grid-ca.pem",
    ]
    old = build(old_ca, cfg)
    new = build(new_ca, cfg + [b"ca_rotation=2026-Q2"])
    with open(os.path.join(HERE, "old.bin"), "wb") as f:
        f.write(old)
    with open(os.path.join(HERE, "new.bin"), "wb") as f:
        f.write(new)
    print("wrote old.bin (%d) new.bin (%d)" % (len(old), len(new)))


if __name__ == "__main__":
    main()
