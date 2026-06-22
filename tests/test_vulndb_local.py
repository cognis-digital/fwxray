from fwxray.vulndb_local import VulnDB
def test_has_100k_plus_vulns(): assert VulnDB().count() >= 100000
def test_detailed_metadata():
    r=next(iter(VulnDB()))
    for f in ("id","aliases","ecosystem","summary","severity","packages"): assert f in r
def test_cve_lookup(): assert isinstance(VulnDB().by_cve("CVE-2021-44228"), list)
