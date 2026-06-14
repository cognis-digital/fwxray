"""Tests for input validation, error handling, and edge-case robustness."""
from __future__ import annotations

import os
import tempfile

import pytest

from fwxray.cli import main
from fwxray.core import diff_firmware, extract_strings, block_entropy_profile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_bin(content: bytes) -> str:
    """Write bytes to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    with open(path, "wb") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# CLI: bad / missing paths
# ---------------------------------------------------------------------------

def test_cli_missing_old_file_exits_2(capsys):
    rc = main(["diff", "/no/such/old.bin", "/no/such/new.bin"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_missing_new_file_exits_2(capsys, tmp_path):
    real = _write_bin(b"firmware payload")
    try:
        rc = main(["diff", real, str(tmp_path / "nonexistent.bin")])
    finally:
        os.unlink(real)
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_directory_as_input_exits_2(capsys, tmp_path):
    """Passing a directory instead of a file must not raise a traceback."""
    rc = main(["diff", str(tmp_path), str(tmp_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


# ---------------------------------------------------------------------------
# CLI: bad argument values
# ---------------------------------------------------------------------------

def test_cli_block_zero_exits_2(capsys, tmp_path):
    a = _write_bin(b"firmware_a")
    b = _write_bin(b"firmware_b")
    try:
        rc = main(["diff", a, b, "--block", "0"])
    finally:
        os.unlink(a)
        os.unlink(b)
    assert rc == 2
    err = capsys.readouterr().err
    assert "block" in err.lower()


def test_cli_block_negative_exits_2(capsys):
    a = _write_bin(b"firmware_a")
    b = _write_bin(b"firmware_b")
    try:
        rc = main(["diff", a, b, "--block", "-512"])
    finally:
        os.unlink(a)
        os.unlink(b)
    assert rc == 2
    err = capsys.readouterr().err
    assert "block" in err.lower()


def test_cli_negative_entropy_threshold_exits_2(capsys):
    a = _write_bin(b"firmware_a")
    b = _write_bin(b"firmware_b")
    try:
        rc = main(["diff", a, b, "--entropy-threshold", "-1.0"])
    finally:
        os.unlink(a)
        os.unlink(b)
    assert rc == 2
    err = capsys.readouterr().err
    assert "entropy" in err.lower()


def test_cli_min_str_len_zero_exits_2(capsys):
    a = _write_bin(b"firmware_a")
    b = _write_bin(b"firmware_b")
    try:
        rc = main(["diff", a, b, "--min-str-len", "0"])
    finally:
        os.unlink(a)
        os.unlink(b)
    assert rc == 2
    err = capsys.readouterr().err
    assert "str" in err.lower()


# ---------------------------------------------------------------------------
# core: edge cases
# ---------------------------------------------------------------------------

def test_diff_firmware_validates_block():
    a = _write_bin(b"hello world firmware")
    b = _write_bin(b"hello world firmware v2")
    try:
        with pytest.raises(ValueError, match="block"):
            diff_firmware(a, b, block=0)
        with pytest.raises(ValueError, match="block"):
            diff_firmware(a, b, block=-1)
    finally:
        os.unlink(a)
        os.unlink(b)


def test_diff_firmware_validates_entropy_threshold():
    a = _write_bin(b"hello world firmware")
    b = _write_bin(b"hello world firmware v2")
    try:
        with pytest.raises(ValueError, match="entropy"):
            diff_firmware(a, b, entropy_threshold=-0.5)
    finally:
        os.unlink(a)
        os.unlink(b)


def test_diff_firmware_validates_min_str_len():
    a = _write_bin(b"hello world firmware")
    b = _write_bin(b"hello world firmware v2")
    try:
        with pytest.raises(ValueError, match="min_str_len"):
            diff_firmware(a, b, min_str_len=0)
    finally:
        os.unlink(a)
        os.unlink(b)


def test_diff_firmware_empty_files():
    """Two empty firmware images are treated as identical."""
    a = _write_bin(b"")
    b = _write_bin(b"")
    try:
        r = diff_firmware(a, b)
        assert r.identical
        assert not r.has_findings()
        assert r.old_size == 0
        assert r.new_size == 0
    finally:
        os.unlink(a)
        os.unlink(b)


def test_diff_firmware_one_empty():
    """One empty image vs non-empty should detect changes."""
    a = _write_bin(b"")
    b = _write_bin(b"\x1f\x8b\x08" + b"\xaa" * 512)
    try:
        r = diff_firmware(a, b)
        assert not r.identical
        assert r.has_findings()
    finally:
        os.unlink(a)
        os.unlink(b)


def test_block_entropy_profile_empty_data():
    """Empty input produces an empty profile — no ZeroDivisionError."""
    result = block_entropy_profile(b"", block=1024)
    assert result == []


def test_extract_strings_empty_data():
    """Empty bytes produces an empty string list."""
    assert extract_strings(b"") == []


def test_mcp_server_imports_cleanly():
    """mcp_server must be importable without a NameError or ImportError
    (the mcp package itself is optional, but our own symbols must resolve)."""
    import importlib
    mod = importlib.import_module("fwxray.mcp_server")
    assert callable(mod.serve)
