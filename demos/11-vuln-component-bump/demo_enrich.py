"""Fully-offline enrichment demo for FWXRAY's OSV/CISA-KEV feeds layer.

Runs with ZERO network: it points COGNIS_FEEDS_CACHE at the committed KEV
fixture and feeds the parser a pre-resolved OSV index built from the committed
trimmed OSV fixtures -- exactly what an air-gapped device carries in its feed
snapshot. Prints the headline known-exploited finding.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
FIX = os.path.join(ROOT, "tests", "fixtures")

# air-gap: serve the KEV catalog from the committed snapshot cache.
os.environ["COGNIS_FEEDS_CACHE"] = os.path.join(FIX, "cache")
sys.path.insert(0, ROOT)

from fwxray.core import diff_firmware  # noqa: E402
from fwxray import feeds  # noqa: E402


def _osv_index():
    def load(name):
        with open(os.path.join(FIX, name), encoding="utf-8") as fh:
            return json.load(fh)["vulns"]
    return {
        "log4j-core 2.14.1": load("osv_log4j_2.14.1.json"),
        "lodash 4.17.4": load("osv_lodash_4.17.4.json"),
        "openssl 1.0.2k": load("osv_openssl_1.0.2k.json"),
    }


def main() -> int:
    # (re)generate the demo images, then diff them.
    import runpy
    runpy.run_path(os.path.join(HERE, "make_images.py"), run_name="__main__")
    diff = diff_firmware(os.path.join(HERE, "old.bin"), os.path.join(HERE, "new.bin"))

    findings = feeds.enrich_strings(
        diff.strings_added, offline=True, osv_index=_osv_index()
    )
    print(f"Scanned {len(diff.strings_added)} added strings -> "
          f"{len(findings)} vulnerable component(s)\n")
    for f in findings:
        flag = "  [KNOWN-EXPLOITED]" if f["known_exploited"] else ""
        print(f"  {f['component']} {f['version']}  "
              f"({f['vuln_count']} vuln){flag}")
        if f["kev_cves"]:
            print(f"      CISA-KEV: {', '.join(f['kev_cves'])}")
    assert any(f["known_exploited"] for f in findings), "expected a KEV hit"
    print("\nOK - air-gap enrichment flagged a known-exploited component.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
