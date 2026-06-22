"""Tests for fwxray ACTIVE acquisition mode.

Every test exercises the authorization/scope/rate-limit gate against a bundled
fixture "device" file (a real path on disk) or an in-memory fake device + fake
clock. NOTHING here touches real hardware or a network host.
"""
import io
import json
import os

import pytest

from fwxray import active as A
from fwxray.cli import main


# --------------------------------------------------------------------------- #
# fixtures: a fake "device" file and an in-memory clock
# --------------------------------------------------------------------------- #
@pytest.fixture
def device_file(tmp_path):
    p = tmp_path / "mtd0.bin"
    p.write_bytes(b"\x7fELF" + b"FWXRAY-DEVICE-IMAGE" * 100)
    return str(p)


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.slept = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        # advance virtual time instead of really sleeping
        self.slept += s
        self.t += s


# --------------------------------------------------------------------------- #
# policy gate: fail-closed by default
# --------------------------------------------------------------------------- #
def test_default_policy_is_off():
    p = A.AcquisitionPolicy()
    assert p.authorized is False
    assert p.allowlist == []


def test_authorize_refuses_without_authorized_flag():
    p = A.AcquisitionPolicy(authorized=False, allowlist=["*"])
    with pytest.raises(A.AuthorizationError):
        p.authorize("/dev/mtd0")


def test_authorize_refuses_empty_allowlist():
    p = A.AcquisitionPolicy(authorized=True, allowlist=[])
    with pytest.raises(A.ScopeError):
        p.authorize("/dev/mtd0")


def test_authorize_refuses_out_of_scope():
    p = A.AcquisitionPolicy(authorized=True, allowlist=["/dev/mtd0"])
    with pytest.raises(A.ScopeError):
        p.authorize("/dev/sda")


def test_authorize_accepts_in_scope_exact():
    p = A.AcquisitionPolicy(authorized=True, allowlist=["/dev/mtd0"])
    p.authorize("/dev/mtd0")  # no raise


def test_authorize_accepts_glob_scope():
    p = A.AcquisitionPolicy(authorized=True, allowlist=["/dev/mtd*"])
    p.authorize("/dev/mtd3")


def test_in_scope_is_false_for_empty_allowlist():
    assert A.AcquisitionPolicy(authorized=True).in_scope("/dev/mtd0") is False


def test_in_scope_glob_and_exact():
    p = A.AcquisitionPolicy(authorized=True, allowlist=["/dev/mtd*", "/tmp/x.bin"])
    assert p.in_scope("/dev/mtd9")
    assert p.in_scope("/tmp/x.bin")
    assert not p.in_scope("/etc/passwd")


# --------------------------------------------------------------------------- #
# policy from env + args
# --------------------------------------------------------------------------- #
def test_policy_merges_env_allowlist(monkeypatch):
    monkeypatch.setenv("FWXRAY_DEVICE_ALLOWLIST", "/dev/a" + os.pathsep + "/dev/b")
    p = A.AcquisitionPolicy.from_env_and_args(authorized=True, allow=["/dev/c"])
    assert "/dev/a" in p.allowlist
    assert "/dev/b" in p.allowlist
    assert "/dev/c" in p.allowlist


def test_policy_env_blank_entries_ignored(monkeypatch):
    monkeypatch.setenv("FWXRAY_DEVICE_ALLOWLIST", os.pathsep + "  " + os.pathsep)
    p = A.AcquisitionPolicy.from_env_and_args(authorized=False, allow=None)
    assert p.allowlist == []


def test_policy_respects_custom_limits():
    p = A.AcquisitionPolicy.from_env_and_args(
        authorized=True, allow=["*"], max_bytes=10, max_bytes_per_sec=5
    )
    assert p.max_bytes == 10
    assert p.max_bytes_per_sec == 5


# --------------------------------------------------------------------------- #
# acquire(): the gate runs before any read
# --------------------------------------------------------------------------- #
def test_acquire_refuses_before_reading(device_file):
    reads = {"count": 0}

    def opener(_src):
        reads["count"] += 1
        return io.BytesIO(b"should-not-be-read")

    p = A.AcquisitionPolicy(authorized=False, allowlist=["*"])
    with pytest.raises(A.AuthorizationError):
        A.acquire(device_file, p, opener=opener)
    assert reads["count"] == 0  # not a single byte read


def test_acquire_reads_in_scope_device(device_file):
    p = A.AcquisitionPolicy(authorized=True, allowlist=[device_file],
                            max_bytes_per_sec=0)
    res = A.acquire(device_file, p)
    assert res.bytes_read == os.path.getsize(device_file)
    assert len(res.sha256) == 64
    assert res.truncated is False


def test_acquire_writes_out_file(device_file, tmp_path):
    out = tmp_path / "pulled.bin"
    p = A.AcquisitionPolicy(authorized=True, allowlist=[device_file],
                            max_bytes_per_sec=0)
    res = A.acquire(device_file, p, out_path=str(out))
    assert out.exists()
    assert out.read_bytes() == open(device_file, "rb").read()
    assert res.out_path == str(out)


def test_acquire_truncates_at_max_bytes(device_file):
    p = A.AcquisitionPolicy(authorized=True, allowlist=[device_file],
                            max_bytes=16, max_bytes_per_sec=0)
    res = A.acquire(device_file, p, chunk=4)
    assert res.bytes_read == 16
    assert res.truncated is True


def test_acquire_uses_injected_opener_and_clock():
    payload = b"X" * 1000
    clock = FakeClock()
    p = A.AcquisitionPolicy(authorized=True, allowlist=["fake://dev"],
                            max_bytes_per_sec=100)  # 100 B/s
    res = A.acquire(
        "fake://dev", p,
        opener=lambda s: io.BytesIO(payload),
        clock=clock.now, sleep=clock.sleep, chunk=100,
    )
    assert res.bytes_read == 1000
    # 1000 bytes at 100 B/s -> ~10s of virtual throttling
    assert clock.slept >= 9.0


def test_acquire_no_throttle_when_rate_zero():
    clock = FakeClock()
    p = A.AcquisitionPolicy(authorized=True, allowlist=["*"], max_bytes_per_sec=0)
    A.acquire("x", p, opener=lambda s: io.BytesIO(b"Y" * 500),
              clock=clock.now, sleep=clock.sleep, chunk=50)
    assert clock.slept == 0.0


def test_acquire_result_to_dict(device_file):
    p = A.AcquisitionPolicy(authorized=True, allowlist=[device_file],
                            max_bytes_per_sec=0)
    d = A.acquire(device_file, p).to_dict()
    assert set(d) == {"source", "bytes_read", "sha256", "truncated",
                      "elapsed_s", "out_path"}


def test_acquire_sha_matches_file_contents(device_file):
    import hashlib
    expected = hashlib.sha256(open(device_file, "rb").read()).hexdigest()
    p = A.AcquisitionPolicy(authorized=True, allowlist=[device_file],
                            max_bytes_per_sec=0)
    assert A.acquire(device_file, p).sha256 == expected


# --------------------------------------------------------------------------- #
# CLI: pull command gating + banner
# --------------------------------------------------------------------------- #
def test_cli_pull_refuses_without_authorized(device_file, capsys):
    rc = main(["pull", device_file])
    err = capsys.readouterr().err
    assert rc == 3
    assert "AUTHORIZED USE ONLY" in err
    assert "REFUSED (authorization)" in err


def test_cli_pull_refuses_without_allowlist(device_file, capsys):
    rc = main(["pull", device_file, "--authorized"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "REFUSED (scope)" in err


def test_cli_pull_refuses_out_of_scope(device_file, capsys, tmp_path):
    other = tmp_path / "other.bin"
    other.write_bytes(b"nope")
    rc = main(["pull", str(other), "--authorized", "--allow", device_file])
    assert rc == 3
    assert "REFUSED (scope)" in capsys.readouterr().err


def test_cli_pull_succeeds_in_scope_json(device_file, capsys):
    rc = main(["pull", device_file, "--authorized", "--allow", device_file,
               "--max-bytes-per-sec", "0", "--format", "json"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "AUTHORIZED USE ONLY" in captured.err  # banner always printed
    payload = json.loads(captured.out)
    assert payload["bytes_read"] == os.path.getsize(device_file)


def test_cli_pull_banner_on_every_invocation(device_file, capsys):
    main(["pull", device_file])  # refused
    assert "AUTHORIZED USE ONLY" in capsys.readouterr().err


def test_cli_pull_writes_out(device_file, capsys, tmp_path):
    out = tmp_path / "img.bin"
    rc = main(["pull", device_file, "--authorized", "--allow", device_file,
               "--max-bytes-per-sec", "0", "--out", str(out)])
    assert rc == 0
    assert out.exists()
    assert "written" in capsys.readouterr().out
