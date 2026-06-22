"""Offline tests for the OSV / CISA-KEV data-feed enrichment layer.

NO NETWORK: ``COGNIS_FEEDS_CACHE`` is pointed at the committed KEV fixture and
the OSV results come from committed trimmed fixtures (an offline OSV index), so
the whole suite runs on an air-gapped box.
"""
import json
import os
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"
CACHE = FIX / "cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    # point datafeeds at the committed KEV cache; guarantees offline reads.
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(CACHE))
    yield


def _osv_index():
    """Build the pre-resolved OSV map from committed trimmed fixtures."""
    def load(name):
        return json.loads((FIX / name).read_text())["vulns"]
    return {
        "log4j-core 2.14.1": load("osv_log4j_2.14.1.json"),
        "lodash 4.17.4": load("osv_lodash_4.17.4.json"),
        "openssl 1.0.2k": load("osv_openssl_1.0.2k.json"),
    }


def test_feed_ids_are_in_bundled_catalog():
    from fwxray import datafeeds, feeds
    ids = {f["id"] for f in datafeeds.load_catalog()["feeds"]}
    for fid in feeds.FEED_IDS:
        assert fid in ids, f"{fid} missing from bundled catalog"
    assert set(feeds.FEED_IDS) == {"osv", "cisa-kev"}


def test_parse_components():
    from fwxray.feeds import parse_components
    strings = [
        "OpenSSL 1.0.2k  1 Mar 2017",
        "BusyBox v1.30.1 (2019-06-12)",
        "lodash/4.17.4",
        "log4j-core-2.14.1.jar",
        "this is just prose with no version",
        "Copyright 2021",
    ]
    comps = parse_components(strings)
    names = {c["name"].lower(): c["version"] for c in comps}
    assert "openssl" in names and names["openssl"].startswith("1.0.2")
    assert "busybox" in names
    assert "lodash" in names
    assert "log4j-core" in names
    # prose / copyright tokens must not become components
    assert "copyright" not in names


def test_normalize_version():
    from fwxray.feeds import normalize_version
    assert normalize_version("1.0.2k") == "1.0.2"
    assert normalize_version("2.14.1") == "2.14.1"
    assert normalize_version("v3.0") == "3.0" or normalize_version("3.0") == "3.0"


def test_load_kev_offline():
    from fwxray.feeds import load_kev
    kev = load_kev(offline=True)
    assert "CVE-2021-44228" in kev  # Log4Shell, real KEV record in fixture
    assert kev["CVE-2021-44228"]["product"]


def test_enrich_flags_known_exploited_offline():
    """The headline enrichment: log4j 2.14.1 -> OSV CVEs -> KEV known-exploited."""
    from fwxray.feeds import enrich_components
    comps = [{"name": "log4j-core", "version": "2.14.1", "raw": "log4j-core-2.14.1"}]
    findings = enrich_components(comps, offline=True, osv_index=_osv_index())
    assert len(findings) == 1
    f = findings[0]
    assert f["component"] == "log4j-core"
    assert f["vuln_count"] >= 1
    assert f["known_exploited"] is True
    assert "CVE-2021-44228" in f["kev_cves"]
    # the specific vuln row is marked exploited
    exploited = [v for v in f["vulns"] if v["known_exploited"]]
    assert any("CVE-2021-44228" in v["kev_cves"] for v in exploited)


def test_enrich_non_kev_component_offline():
    """A vulnerable-but-not-KEV component reports vulns without the exploit flag."""
    from fwxray.feeds import enrich_components
    comps = [{"name": "lodash", "version": "4.17.4", "raw": "lodash 4.17.4"}]
    findings = enrich_components(comps, offline=True, osv_index=_osv_index())
    assert len(findings) == 1
    assert findings[0]["vuln_count"] >= 1
    assert findings[0]["known_exploited"] is False


def test_enrich_orders_known_exploited_first():
    from fwxray.feeds import enrich_components
    comps = [
        {"name": "lodash", "version": "4.17.4", "raw": "lodash 4.17.4"},
        {"name": "log4j-core", "version": "2.14.1", "raw": "log4j-core-2.14.1"},
    ]
    findings = enrich_components(comps, offline=True, osv_index=_osv_index())
    assert findings[0]["known_exploited"] is True  # KEV component sorts first


def test_enrich_offline_without_index_is_safe():
    """Offline with no OSV index: no crash, KEV still loads, just no OSV vulns."""
    from fwxray.feeds import enrich_components
    comps = [{"name": "log4j-core", "version": "2.14.1", "raw": "x"}]
    findings = enrich_components(comps, offline=True)
    assert findings == []  # nothing to report without OSV resolution


def test_cli_feeds_list(capsys):
    from fwxray.cli import main
    rc = main(["feeds", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "osv" in out and "cisa-kev" in out


def test_cli_feeds_get_offline(capsys):
    from fwxray.cli import main
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE-2021-44228" in out


def test_cli_feeds_rejects_unknown_feed():
    from fwxray.cli import main
    with pytest.raises(SystemExit):  # argparse choices reject non-catalog ids
        main(["feeds", "get", "ofac-sdn", "--offline"])
