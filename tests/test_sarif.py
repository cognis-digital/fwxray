"""Tests for the SARIF 2.1.0 export."""
import json
import os
import runpy

import pytest

from fwxray.cli import main
from fwxray.core import diff_firmware, to_sarif

DEMOS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")


@pytest.fixture(scope="module")
def diff_result():
    demo = os.path.join(DEMOS, "05-debug-backdoor")
    runpy.run_path(os.path.join(demo, "make_images.py"), run_name="__main__")
    return diff_firmware(
        os.path.join(demo, "old.bin"), os.path.join(demo, "new.bin")
    )


def test_sarif_envelope(diff_result):
    doc = to_sarif(diff_result)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "fwxray"
    assert driver["version"].count(".") == 2
    assert driver["rules"], "expected rule metadata"


def test_sarif_results_reference_known_rules(diff_result):
    doc = to_sarif(diff_result)
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    results = run["results"]
    assert results, "debug-backdoor demo should yield results"
    for res in results:
        assert res["ruleId"] in rule_ids
        assert res["message"]["text"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    # The flipped telnet flag must show up as a flag-flipped result.
    assert any(
        r["ruleId"] == "fwx-flag-flipped" and "telnetd" in r["message"]["text"]
        for r in results
    )


def test_sarif_identical_has_no_results():
    demo = os.path.join(DEMOS, "09-identical-resign")
    runpy.run_path(os.path.join(demo, "make_images.py"), run_name="__main__")
    r = diff_firmware(
        os.path.join(demo, "old.bin"), os.path.join(demo, "new.bin")
    )
    doc = to_sarif(r)
    assert doc["runs"][0]["results"] == []


def test_cli_sarif_format(capsys):
    demo = os.path.join(DEMOS, "04-telemetry-added")
    runpy.run_path(os.path.join(demo, "make_images.py"), run_name="__main__")
    capsys.readouterr()  # discard generator's stdout before capturing CLI output
    rc = main([
        "diff",
        os.path.join(demo, "old.bin"),
        os.path.join(demo, "new.bin"),
        "--format", "sarif",
    ])
    out = capsys.readouterr().out
    assert rc == 1
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]
