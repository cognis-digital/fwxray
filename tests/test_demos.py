"""Tests that every shipped demo regenerates and produces its intended result.

Each demo folder carries a make_images.py that deterministically writes
old.bin / new.bin. We regenerate them (hermetic) and assert the headline
finding the demo's SCENARIO.md promises actually fires.
"""
import os
import runpy

import pytest

from fwxray.core import diff_firmware

DEMOS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")


def _gen(demo: str):
    runpy.run_path(os.path.join(DEMOS, demo, "make_images.py"), run_name="__main__")
    old = os.path.join(DEMOS, demo, "old.bin")
    new = os.path.join(DEMOS, demo, "new.bin")
    assert os.path.exists(old) and os.path.exists(new)
    return diff_firmware(old, new)


def test_02_clean_is_identical():
    r = _gen("02-clean")
    assert r.identical
    assert not r.has_findings()


def test_03_mixed_multi_axis():
    r = _gen("03-mixed")
    assert r.has_findings()
    assert "fw_version" in r.flags_flipped
    assert any(s["label"] == "zip" for s in r.sections_added)
    assert r.entropy_shifts
    assert any("new-ui-bundle" in s for s in r.strings_added)


def test_04_telemetry_added():
    r = _gen("04-telemetry-added")
    assert r.has_findings()
    assert r.flags_flipped["analytics"]["new"] == "on"
    assert r.flags_flipped["telemetry_optout"]["new"] == "false"
    assert "metrics_endpoint" in r.flags_added


def test_05_debug_backdoor():
    r = _gen("05-debug-backdoor")
    assert r.has_findings()
    assert r.flags_flipped["telnetd"]["new"] == "enabled"
    assert r.flags_flipped["ssh_root_login"]["new"] == "yes"
    assert "debug_shell" in r.flags_added


def test_06_cert_rotation_is_clean_swap():
    r = _gen("06-cert-rotation")
    assert r.has_findings()
    # The only flag change should be the expected rotation marker.
    assert "ca_rotation" in r.flags_added
    assert r.flags_flipped == {}
    # The PEM/cert content changed (visible as string deltas).
    assert r.strings_added and r.strings_removed


def test_07_encrypted_partition_entropy_spike():
    r = _gen("07-encrypted-partition")
    assert r.has_findings()
    assert r.flags_flipped["rootfs"]["new"] == "luks-aes256"
    assert r.entropy_shifts
    assert max(e["delta"] for e in r.entropy_shifts) > 2.0


def test_08_version_downgrade():
    r = _gen("08-version-downgrade")
    assert r.has_findings()
    assert r.flags_flipped["fw_version"]["old"] == "7.5.2"
    assert r.flags_flipped["fw_version"]["new"] == "7.4.0"
    assert r.flags_flipped["sslv3_enabled"]["new"] == "true"


def test_09_identical_resign():
    r = _gen("09-identical-resign")
    assert r.identical
    assert not r.has_findings()


def test_10_squashfs_grow():
    r = _gen("10-squashfs-grow")
    assert r.has_findings()
    grew = [s for s in r.sections_changed if s["label"].startswith("squashfs")]
    assert grew and grew[0]["size_delta"] > 0
    assert any("wireguard-go" in s for s in r.strings_added)


@pytest.mark.parametrize(
    "demo",
    [
        "01-basic", "02-clean", "03-mixed", "04-telemetry-added",
        "05-debug-backdoor", "06-cert-rotation", "07-encrypted-partition",
        "08-version-downgrade", "09-identical-resign", "10-squashfs-grow",
    ],
)
def test_every_demo_has_scenario_and_generator(demo):
    folder = os.path.join(DEMOS, demo)
    assert os.path.exists(os.path.join(folder, "SCENARIO.md"))
    assert os.path.exists(os.path.join(folder, "make_images.py"))
