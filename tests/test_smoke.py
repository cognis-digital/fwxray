"""Smoke tests for FWXRAY. Imports the engine, builds the demo images, and
asserts real diff behavior. No network access.
"""
import json
import os
import runpy
import subprocess
import sys

import pytest

from fwxray import (
    TOOL_NAME,
    TOOL_VERSION,
    carve_sections,
    diff_firmware,
    extract_strings,
    shannon_entropy,
)
from fwxray.cli import main

DEMO_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos", "01-basic")


@pytest.fixture(scope="module")
def images():
    # (Re)generate the demo images deterministically so the test is hermetic.
    runpy.run_path(os.path.join(DEMO_DIR, "make_images.py"), run_name="__main__")
    old = os.path.join(DEMO_DIR, "old.bin")
    new = os.path.join(DEMO_DIR, "new.bin")
    assert os.path.exists(old) and os.path.exists(new)
    return old, new


def test_metadata():
    assert TOOL_NAME == "fwxray"
    assert TOOL_VERSION.count(".") == 2


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    # All 256 byte values once -> max entropy 8 bits/byte.
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_carve_finds_gzip(images):
    _old, new = images
    with open(new, "rb") as f:
        data = f.read()
    labels = {s.label for s in carve_sections(data)}
    assert "gzip" in labels


def test_extract_strings(images):
    old, _new = images
    with open(old, "rb") as f:
        data = f.read()
    strings = extract_strings(data)
    assert any("fw_version=1.2.3" in s for s in strings)


def test_diff_detects_changes(images):
    old, new = images
    r = diff_firmware(old, new)
    assert r.has_findings()
    assert not r.identical
    # Flag changes from old->new.
    assert "debug" in r.flags_flipped
    assert r.flags_flipped["debug"]["old"] == "0"
    assert r.flags_flipped["debug"]["new"] == "1"
    assert "fw_version" in r.flags_flipped
    assert "feature_x" in r.flags_added
    # The randomized tail should register as a high-entropy shift.
    assert r.entropy_shifts, "expected at least one entropy shift"
    assert max(e["delta"] for e in r.entropy_shifts) > 3.0


def test_identical_has_no_findings(images):
    old, _new = images
    r = diff_firmware(old, old)
    assert r.identical
    assert not r.has_findings()


def test_cli_table_exit_code(images, capsys):
    old, new = images
    rc = main(["diff", old, new])
    out = capsys.readouterr().out
    assert rc == 1  # differ -> CI gate fires
    assert "FWXRAY firmware changelog" in out
    assert "Entropy shifts" in out


def test_cli_json_is_valid(images, capsys):
    old, new = images
    rc = main(["diff", old, new, "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 1
    payload = json.loads(out)
    assert payload["identical"] is False
    assert payload["flags_flipped"]["debug"]["new"] == "1"


def test_cli_identical_exit_zero(images, capsys):
    old, _new = images
    rc = main(["diff", old, old])
    assert rc == 0


def test_module_entrypoint_version():
    proc = subprocess.run(
        [sys.executable, "-m", "fwxray", "--version"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "fwxray" in proc.stdout
