"""Deeper unit tests for fwxray.core primitives. All offline, pure functions."""
import math

import pytest

from fwxray import core
from fwxray.core import (
    shannon_entropy,
    block_entropy_profile,
    carve_sections,
    extract_strings,
    diff_strings,
    diff_firmware,
    to_sarif,
)


# ---- entropy ------------------------------------------------------------- #
def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_entropy_single_symbol():
    assert shannon_entropy(b"AAAA") == 0.0


def test_entropy_two_equiprobable():
    assert abs(shannon_entropy(b"\x00\x01") - 1.0) < 1e-9


def test_entropy_four_equiprobable():
    assert abs(shannon_entropy(bytes([0, 1, 2, 3])) - 2.0) < 1e-9


def test_entropy_full_byte_range():
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_entropy_is_rounded_to_4dp():
    e = shannon_entropy(b"abcdefg")
    assert e == round(e, 4)


def test_entropy_monotone_with_diversity():
    low = shannon_entropy(b"aaaaab")
    high = shannon_entropy(b"abcdef")
    assert high > low


# ---- block entropy profile ---------------------------------------------- #
def test_block_profile_lengths():
    data = b"\x00" * 1000
    prof = block_entropy_profile(data, block=256)
    assert len(prof) == math.ceil(1000 / 256)


def test_block_profile_zero_block_raises():
    with pytest.raises(ValueError):
        block_entropy_profile(b"abc", block=0)


def test_block_profile_empty():
    assert block_entropy_profile(b"", block=64) == []


# ---- carving ------------------------------------------------------------- #
def test_carve_empty_is_empty():
    assert carve_sections(b"") == []


def test_carve_no_magic_is_single_raw():
    secs = carve_sections(b"\x00" * 1000)
    assert len(secs) == 1
    assert secs[0].label == "raw"


def test_carve_leading_raw_before_magic():
    data = b"\x11" * 300 + b"\x7fELF" + b"\x00" * 300
    secs = carve_sections(data)
    assert secs[0].label == "raw"
    assert any(s.label == "elf" for s in secs)


def test_carve_min_block_collapses_close_hits():
    data = b"\x7fELF" + b"\x00" * 10 + b"\x7fELF" + b"\x00" * 400
    secs = carve_sections(data)
    # second ELF within min_block (256) of the first is collapsed
    assert sum(1 for s in secs if s.label == "elf") == 1


def test_carve_section_has_sha_and_entropy():
    data = b"\x7fELF" + b"\x00" * 400
    s = carve_sections(data)[0]
    assert len(s.sha256) == 64
    assert s.size > 0
    assert s.offset == 0


def test_carve_multiple_distinct_magics():
    data = (b"\x7fELF" + b"\x00" * 400
            + b"\x1f\x8b\x08" + b"\x00" * 400
            + b"hsqs" + b"\x00" * 400)
    labels = {s.label for s in carve_sections(data)}
    assert {"elf", "gzip", "squashfs(le)"} <= labels


# ---- strings ------------------------------------------------------------- #
def test_extract_strings_min_len():
    data = b"\x00ab\x00abcd\x00abcdef\x00"
    out = extract_strings(data, min_len=4)
    assert "abcd" in out
    assert "abcdef" in out
    assert "ab" not in out


def test_extract_strings_min_len_zero_raises():
    with pytest.raises(ValueError):
        extract_strings(b"abc", min_len=0)


def test_extract_strings_empty():
    assert extract_strings(b"") == []


def test_diff_strings_added_removed():
    old = b"alpha\x00bravo\x00"
    new = b"bravo\x00charlie\x00"
    added, removed = diff_strings(old, new)
    assert "charlie" in added
    assert "alpha" in removed


# ---- flags --------------------------------------------------------------- #
def test_parse_flags_keyvalue():
    flags = core._parse_flags(["debug=1", "name: device", "garbage prose here"])
    assert flags["debug"] == "1"
    assert flags["name"] == "device"


def test_parse_flags_rejects_spaced_keys():
    flags = core._parse_flags(["this is = bad"])
    assert "this is" not in flags


def test_diff_flags_added_removed_flipped():
    old = {"a": "1", "b": "2"}
    new = {"b": "3", "c": "4"}
    added, removed, flipped = core._diff_flags(old, new)
    assert added == {"c": "4"}
    assert removed == {"a": "1"}
    assert flipped == {"b": {"old": "2", "new": "3"}}


# ---- diff_firmware ------------------------------------------------------- #
def test_diff_identical_files(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 500)
    r = diff_firmware(str(p), str(p))
    assert r.identical
    assert not r.has_findings()


def test_diff_missing_file_raises(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")
    with pytest.raises(FileNotFoundError):
        diff_firmware(str(p), "/no/such.bin")


def test_diff_records_sizes_and_shas(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"\x00" * 100)
    b.write_bytes(b"\x00" * 200)
    r = diff_firmware(str(a), str(b))
    assert r.old_size == 100
    assert r.new_size == 200
    assert r.old_sha256 != r.new_sha256


# ---- SARIF --------------------------------------------------------------- #
def test_sarif_schema_and_version(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"debug=0\n" + b"\x00" * 2000)
    b.write_bytes(b"debug=1\n" + bytes(range(256)) * 8)
    sarif = to_sarif(diff_firmware(str(a), str(b)))
    assert sarif["version"] == "2.1.0"
    assert "sarif-2.1.0" in sarif["$schema"]
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "fwxray"


def test_sarif_emits_results_for_flag_flip(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"debug=0\n" + b"\x00" * 2000)
    b.write_bytes(b"debug=1\n" + b"\x00" * 2000)
    sarif = to_sarif(diff_firmware(str(a), str(b)))
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "fwx-flag-flipped" in rule_ids


def test_sarif_rules_declared():
    # all rule ids referenced in _SARIF_RULES should appear in the driver rules
    ids = {rid for rid, _d, _l in core._SARIF_RULES}
    assert "fwx-entropy-shift" in ids
    assert "fwx-section-added" in ids
