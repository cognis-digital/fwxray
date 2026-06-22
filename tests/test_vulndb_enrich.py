"""Tests that the bundled 262k-record offline vuln DB is wired into enrichment.

Fully offline: KEV is read from the committed fixture cache; OSV is never
queried (offline=True), so all vulns here come from the bundled corpus.
"""
import os
from pathlib import Path

import pytest

from fwxray import feeds
from fwxray.vulndb_local import VulnDB

FIX = Path(__file__).parent / "fixtures"
CACHE = FIX / "cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(CACHE))
    yield


def _comp(name, ver):
    return {"name": name, "version": ver, "raw": f"{name} {ver}"}


def test_bundle_present_and_large():
    assert VulnDB().count() >= 100000


def test_query_vulndb_log4j_resolves_leaf():
    vulns = feeds.query_vulndb("log4j-core", "2.14.1")
    assert vulns, "expected bundled vulndb hits for log4j-core"
    ids = {v.get("id") for v in vulns}
    aliases = {a for v in vulns for a in (v.get("aliases") or [])}
    assert "CVE-2021-44228" in (ids | aliases)


def test_query_vulndb_unknown_returns_empty():
    assert feeds.query_vulndb("definitely-not-a-real-pkg-xyzzy", "9.9.9") == []


def test_query_vulndb_respects_max_hits():
    vulns = feeds.query_vulndb("openssl", "1.0.2k", max_hits=3)
    assert len(vulns) <= 3


def test_offline_enrich_uses_bundle():
    findings = feeds.enrich_components([_comp("log4j-core", "2.14.1")], offline=True)
    assert len(findings) == 1
    assert findings[0]["vuln_count"] >= 1


def test_offline_enrich_flags_known_exploited():
    findings = feeds.enrich_components([_comp("log4j-core", "2.14.1")], offline=True)
    assert findings[0]["known_exploited"] is True
    assert "CVE-2021-44228" in findings[0]["kev_cves"]


def test_offline_enrich_can_disable_vulndb():
    findings = feeds.enrich_components(
        [_comp("log4j-core", "2.14.1")], offline=True, use_vulndb=False
    )
    assert findings == []  # no OSV index, no bundle -> nothing


def test_offline_enrich_openssl_has_many():
    findings = feeds.enrich_components([_comp("openssl", "1.0.2k")], offline=True)
    assert findings and findings[0]["vuln_count"] >= 1


def test_enrich_strings_offline_end_to_end():
    strings = ["log4j-core 2.14.1", "some prose that is not a component"]
    findings = feeds.enrich_strings(strings, offline=True)
    comps = {f["component"].lower() for f in findings}
    assert "log4j-core" in comps


def test_singleton_db_is_reused():
    feeds._VDB = None
    feeds.query_vulndb("openssl", "1.0.0")
    first = feeds._VDB
    feeds.query_vulndb("zlib", "1.2.11")
    assert feeds._VDB is first
