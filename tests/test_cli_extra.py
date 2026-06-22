"""Additional CLI tests: scan, feeds, sarif output, help/error paths. Offline."""
import json
import os
from pathlib import Path

import pytest

from fwxray.cli import main, build_parser

FIX = Path(__file__).parent / "fixtures"
CACHE = FIX / "cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(CACHE))
    yield


@pytest.fixture
def vuln_images(tmp_path):
    old = tmp_path / "old.bin"
    new = tmp_path / "new.bin"
    old.write_bytes(b"\x7fELF\x00" + b"baseline string\n" + b"\x00" * 300)
    new.write_bytes(b"\x7fELF\x00" + b"log4j-core 2.14.1\x00" + b"\x00" * 300)
    return str(old), str(new)


# ---- parser -------------------------------------------------------------- #
def test_parser_builds():
    p = build_parser()
    assert p.prog == "fwxray"


def test_parser_has_all_commands():
    p = build_parser()
    sub = [a for a in p._actions if hasattr(a, "choices") and a.choices
           and "diff" in a.choices]
    assert sub
    cmds = set(sub[0].choices)
    assert {"diff", "scan", "feeds", "inspect", "pull"} <= cmds


def test_no_command_prints_help():
    rc = main([])
    assert rc == 2


# ---- scan ---------------------------------------------------------------- #
def test_scan_offline_table(vuln_images, capsys):
    old, new = vuln_images
    rc = main(["scan", old, new, "--offline"])
    out = capsys.readouterr().out
    assert "component vulnerability scan" in out
    # log4j-core resolves to a KNOWN-EXPLOITED component via the bundle
    assert rc == 1
    assert "KNOWN-EXPLOITED" in out


def test_scan_offline_json(vuln_images, capsys):
    old, new = vuln_images
    rc = main(["scan", old, new, "--offline", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert "findings" in payload
    assert any(f["component"].lower() == "log4j-core" for f in payload["findings"])
    assert rc == 1


def test_scan_clean_exit_zero(tmp_path, capsys):
    old = tmp_path / "a.bin"
    new = tmp_path / "b.bin"
    old.write_bytes(b"\x7fELF" + b"\x00" * 300)
    new.write_bytes(b"\x7fELF" + b"harmless update\n" + b"\x00" * 300)
    rc = main(["scan", str(old), str(new), "--offline"])
    assert rc == 0


def test_scan_missing_file(capsys):
    rc = main(["scan", "/no/a.bin", "/no/b.bin", "--offline"])
    assert rc == 2


# ---- feeds --------------------------------------------------------------- #
def test_feeds_list(capsys):
    rc = main(["feeds", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "osv" in out
    assert "cisa-kev" in out


def test_feeds_get_kev_offline(capsys):
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE" in out or "vulnerabilities" in out


def test_feeds_no_subcommand(capsys):
    rc = main(["feeds"])
    assert rc == 2


# ---- sarif --------------------------------------------------------------- #
def test_diff_sarif_output(vuln_images, capsys):
    old, new = vuln_images
    rc = main(["diff", old, new, "--format", "sarif"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "fwxray"
    assert rc == 1


def test_diff_block_and_threshold_args(vuln_images, capsys):
    old, new = vuln_images
    rc = main(["diff", old, new, "--block", "512", "--entropy-threshold", "0.5"])
    assert rc in (0, 1)
