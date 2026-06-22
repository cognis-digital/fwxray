"""Tests for the passive single-image `inspect` mode. All offline, read-only."""
import json

import pytest

from fwxray.core import inspect_firmware, FirmwareReport
from fwxray.cli import main


@pytest.fixture
def backdoor_img(tmp_path):
    """A small ELF-ish image with telltale insecure config strings."""
    body = (
        b"\x7fELF" + b"\x00" * 60
        + b"fw_version=5.1.0\n"
        + b"telnetd=enabled\n"
        + b"debug=1\n"
        + b"password=admin123\n"
        + b"-----BEGIN RSA PRIVATE KEY-----\n"
        + b"AKIAIOSFODNN7EXAMPLE\n"
        + b"backdoor_shell=/bin/sh\n"
        + b"\x00" * 200
    )
    p = tmp_path / "fw.bin"
    p.write_bytes(body)
    return str(p)


@pytest.fixture
def clean_img(tmp_path):
    p = tmp_path / "clean.bin"
    p.write_bytes(b"\x7fELF" + b"normal_app_string here\n" + b"\x00" * 300)
    return str(p)


def test_report_basic_shape(clean_img):
    r = inspect_firmware(clean_img)
    assert isinstance(r, FirmwareReport)
    assert r.size > 0
    assert len(r.sha256) == 64
    assert 0.0 <= r.overall_entropy <= 8.0
    assert 0.0 <= r.high_entropy_ratio <= 1.0


def test_report_carves_elf(clean_img):
    r = inspect_firmware(clean_img)
    assert any(s["label"] == "elf" for s in r.sections)


def test_report_extracts_flags(backdoor_img):
    r = inspect_firmware(backdoor_img)
    assert r.flags.get("fw_version") == "5.1.0"
    assert r.flags.get("telnetd") == "enabled"


def test_report_string_count(backdoor_img):
    r = inspect_firmware(backdoor_img)
    assert r.string_count >= 5


def test_indicator_private_key(backdoor_img):
    r = inspect_firmware(backdoor_img)
    kinds = {i["indicator"] for i in r.indicators}
    assert "private-key" in kinds


def test_indicator_hardcoded_credential(backdoor_img):
    r = inspect_firmware(backdoor_img)
    assert "hardcoded-credential" in {i["indicator"] for i in r.indicators}


def test_indicator_aws_key(backdoor_img):
    r = inspect_firmware(backdoor_img)
    assert "aws-access-key-id" in {i["indicator"] for i in r.indicators}


def test_indicator_telnet(backdoor_img):
    r = inspect_firmware(backdoor_img)
    assert "telnet-daemon" in {i["indicator"] for i in r.indicators}


def test_indicator_debug_enabled(backdoor_img):
    r = inspect_firmware(backdoor_img)
    assert "debug-enabled" in {i["indicator"] for i in r.indicators}


def test_indicator_backdoor(backdoor_img):
    r = inspect_firmware(backdoor_img)
    assert "backdoor-string" in {i["indicator"] for i in r.indicators}


def test_indicators_levels_are_valid(backdoor_img):
    r = inspect_firmware(backdoor_img)
    for i in r.indicators:
        assert i["level"] in {"warning", "note"}


def test_indicators_deduped_per_kind(backdoor_img):
    r = inspect_firmware(backdoor_img)
    kinds = [i["indicator"] for i in r.indicators]
    assert len(kinds) == len(set(kinds))  # one example per kind


def test_clean_image_no_warning_indicators(clean_img):
    r = inspect_firmware(clean_img)
    assert not any(i["level"] == "warning" for i in r.indicators)


def test_report_to_dict_roundtrips(backdoor_img):
    r = inspect_firmware(backdoor_img)
    d = r.to_dict()
    assert d["path"] == backdoor_img
    assert "indicators" in d
    json.dumps(d)  # must be JSON-serializable


def test_inspect_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        inspect_firmware("/no/such/firmware.bin")


def test_inspect_empty_image(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    r = inspect_firmware(str(p))
    assert r.size == 0
    assert r.overall_entropy == 0.0
    assert r.high_entropy_ratio == 0.0
    assert r.sections == []


# ---- CLI ----------------------------------------------------------------- #
def test_cli_inspect_table(backdoor_img, capsys):
    rc = main(["inspect", backdoor_img])
    out = capsys.readouterr().out
    assert "firmware inspection (passive)" in out
    assert "Security indicators" in out
    assert rc == 1  # warning-level indicators present -> CI gate fires


def test_cli_inspect_clean_exit_zero(clean_img, capsys):
    rc = main(["inspect", clean_img])
    assert rc == 0


def test_cli_inspect_json(backdoor_img, capsys):
    rc = main(["inspect", backdoor_img, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["path"] == backdoor_img
    assert isinstance(payload["sections"], list)
    assert rc == 1


def test_cli_inspect_missing_file(capsys):
    rc = main(["inspect", "/no/such.bin"])
    assert rc == 2
    assert "error" in capsys.readouterr().err
