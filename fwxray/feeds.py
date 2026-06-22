"""fwxray.feeds — edge/air-gap data-feed enrichment for firmware diffs.

FWXRAY carves printable strings out of a firmware image. An OTA that bumps a
bundled library leaves its fingerprint in those strings (``OpenSSL 1.0.2k``,
``BusyBox v1.30.1``, ``zlib 1.2.11`` ...). This module turns that observation
into a *real* vulnerability finding:

  1. parse ``name + version`` component tokens out of firmware strings, and
  2. query **OSV.dev** (``osv``) for known vulnerabilities affecting that exact
     version across ecosystems, then
  3. cross-reference every resulting CVE against the **CISA Known Exploited
     Vulnerabilities** catalog (``cisa-kev``) and raise a ``known_exploited``
     flag — the highest-priority "patch this now" signal for a fielded device.

Only the two catalog feeds this repo consumes are used: ``osv`` and ``cisa-kev``.

Edge / air-gap
--------------
The bundled :mod:`fwxray.datafeeds` fetches feeds over keyless HTTPS, caches
them to ``COGNIS_FEEDS_CACHE``, and re-serves them with ``offline=True`` so a
disconnected device keeps enriching from the last snapshot. ``cisa-kev`` is a
bulk catalog that caches cleanly; ``osv`` is a per-query POST API, so for the
air gap we pre-resolve the component->vulns map online and ship it inside the
KEV snapshot via :func:`snapshot_workflow` (see README). When fully offline we
fall back to the cached KEV catalog alone, which still flags any component whose
CVE is known-exploited.

Defensive / authorized-use only.
"""
from __future__ import annotations

import json
import re
from typing import Dict, Iterable, List, Optional

from fwxray import datafeeds

# Feed ids this repo is allowed to consume (must exist in the bundled catalog).
FEED_IDS = ("osv", "cisa-kev")

# ecosystem guesses for bare component names, best-effort, most-firmware-ish first.
_ECOSYSTEMS = ("Debian", "Alpine", "PyPI", "npm", "Go", "Maven", "crates.io")

# Firmware strings carry short names; OSV wants ecosystem-qualified coordinates.
# Map well-known bundled-library names to (ecosystem, package) so the live query
# resolves. Extend as needed; unknown names fall back to the ecosystem sweep.
_ALIASES: Dict[str, tuple] = {
    "log4j-core": ("Maven", "org.apache.logging.log4j:log4j-core"),
    "log4j": ("Maven", "org.apache.logging.log4j:log4j-core"),
    "openssl": ("Alpine", "openssl"),
    "busybox": ("Alpine", "busybox"),
    "zlib": ("Alpine", "zlib"),
    "curl": ("Alpine", "curl"),
    "dnsmasq": ("Debian", "dnsmasq"),
    "dropbear": ("Alpine", "dropbear"),
    "wpa_supplicant": ("Alpine", "wpa_supplicant"),
}

# component-name + version tokens, e.g. "OpenSSL 1.0.2k", "busybox v1.30.1",
# "zlib/1.2.11", "curl-7.64.0". Keep names conservative to avoid prose noise.
_COMPONENT = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_+\-]{1,30}?)[ /_\-]v?"
    r"(\d+\.\d+(?:\.\d+)?[a-z]?)"          # 1.0.2 / 1.0.2k; file-ext .jar left alone
)
# obvious non-components to drop (dates, copyrights, version-strings of fwxray).
_STOP = {"http", "https", "version", "copyright", "build", "rev", "revision"}


def normalize_version(ver: str) -> str:
    """Trim a firmware version token to the OSV-friendly numeric core (1.0.2k -> 1.0.2)."""
    m = re.match(r"\d+\.\d+(?:\.\d+)?", ver)
    return m.group(0) if m else ver


def parse_components(strings: Iterable[str]) -> List[Dict[str, str]]:
    """Extract de-duplicated ``{name, version, raw}`` component tokens from strings."""
    seen = set()
    out: List[Dict[str, str]] = []
    for s in strings:
        for m in _COMPONENT.finditer(s):
            name, ver = m.group(1), m.group(2)
            low = name.lower()
            if low in _STOP or len(low) < 3:
                continue
            key = (low, normalize_version(ver))
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": name, "version": ver, "raw": m.group(0)})
    return out


# --------------------------------------------------------------------------- #
# CISA-KEV
# --------------------------------------------------------------------------- #
def load_kev(*, offline: bool = False) -> Dict[str, dict]:
    """Return a ``{CVE-id: kev-record}`` map from the cached/fetched KEV catalog."""
    data = datafeeds.get("cisa-kev", offline=offline)
    out: Dict[str, dict] = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if cve:
            out[cve.upper()] = v
    return out


# --------------------------------------------------------------------------- #
# OSV
# --------------------------------------------------------------------------- #
def _osv_query(name: str, version: str, ecosystem: str) -> List[dict]:
    """One OSV query for an exact name+version+ecosystem (online)."""
    res = datafeeds.get(
        "osv",
        offline=False,
        max_age_hours=0.0,  # OSV is a query API; never serve a stale POST body
        query={"version": version, "package": {"name": name, "ecosystem": ecosystem}},
    )
    return res.get("vulns", []) if isinstance(res, dict) else []


def query_osv(name: str, version: str,
              ecosystems: Iterable[str] = _ECOSYSTEMS) -> List[dict]:
    """Query OSV across candidate ecosystems; return merged, de-duplicated vulns.

    Online only (OSV is a per-query POST API). For air-gapped enrichment use the
    pre-resolved map produced by :func:`build_offline_index`.
    """
    by_id: Dict[str, dict] = {}
    ver = normalize_version(version)
    # Prefer a known coordinate so short firmware names resolve on the right ecosystem.
    alias = _ALIASES.get(name.lower())
    if alias:
        eco, pkg = alias
        try:
            for v in _osv_query(pkg, ver, eco):
                by_id[v.get("id", "")] = v
        except Exception:
            pass
        if by_id:
            return list(by_id.values())
    for eco in ecosystems:
        try:
            vulns = _osv_query(name, ver, eco)
        except Exception:  # network / unknown ecosystem -> skip, try the next
            continue
        for v in vulns:
            by_id[v.get("id", "")] = v
        if vulns:
            break  # first ecosystem that matches is almost always the right one
    return list(by_id.values())


def _cves_of(vuln: dict) -> List[str]:
    """Pull CVE ids from an OSV record (id + aliases)."""
    ids = [vuln.get("id", "")] + list(vuln.get("aliases", []))
    return [i.upper() for i in ids if i.upper().startswith("CVE-")]


# --------------------------------------------------------------------------- #
# bundled offline vuln DB (262k records) — air-gap fallback for OSV
# --------------------------------------------------------------------------- #
_VDB = None  # lazily-loaded singleton


def _vulndb():
    """Return a cached VulnDB instance (the bundled offline corpus)."""
    global _VDB
    if _VDB is None:
        from fwxray.vulndb_local import VulnDB
        _VDB = VulnDB()
    return _VDB


def query_vulndb(name: str, version: str = "", *, max_hits: int = 50) -> List[dict]:
    """Resolve a component against the bundled offline vuln DB by package name.

    Used as the air-gap fallback when no live OSV / pre-resolved index is
    available. Package names in the bundle are ecosystem-qualified
    (``org.apache.logging.log4j:log4j-core``), so we match on the package leaf
    (the part after the last ``:`` or ``/``) as well as the exact alias
    coordinate. Returns OSV-shaped records so the enrichment pipeline is
    unchanged.
    """
    db = _vulndb()
    if db.count() == 0:  # bundle missing / empty
        return []

    wanted = {name.lower()}
    alias = _ALIASES.get(name.lower())
    if alias:
        coord = alias[1].lower()
        wanted.add(coord)
        wanted.add(coord.split(":")[-1])

    def _leaf(pkg: str) -> str:
        return pkg.lower().rsplit(":", 1)[-1].rsplit("/", 1)[-1]

    seen: set = set()
    out: List[dict] = []
    for r in db:
        pkgs = r.get("packages") or []
        if any(p.lower() in wanted or _leaf(p) in wanted for p in pkgs):
            rid = r.get("id")
            if rid and rid not in seen:
                seen.add(rid)
                out.append(r)
                if len(out) >= max_hits:
                    break
    return out


# --------------------------------------------------------------------------- #
# enrichment
# --------------------------------------------------------------------------- #
def enrich_components(components: List[Dict[str, str]], *,
                      offline: bool = False,
                      osv_index: Optional[Dict[str, List[dict]]] = None,
                      use_vulndb: bool = True) -> List[dict]:
    """Map each component to OSV vulns and flag CISA-KEV known-exploited CVEs.

    Parameters
    ----------
    offline:
        When True, never touch the network. OSV results come only from
        ``osv_index`` (a pre-resolved ``"name version" -> [osv vulns]`` map,
        e.g. from a snapshot); the KEV catalog is read from cache.
    osv_index:
        Optional pre-resolved OSV map for air-gap use.

    Returns a list of finding dicts, one per component that has >=1 vuln.
    """
    kev = load_kev(offline=offline)
    findings: List[dict] = []
    for comp in components:
        key = f"{comp['name'].lower()} {normalize_version(comp['version'])}"
        if osv_index is not None:
            vulns = osv_index.get(key, [])
        elif offline:
            # no live OSV when offline: fall back to the bundled vuln DB.
            vulns = query_vulndb(comp["name"], comp["version"]) if use_vulndb else []
        else:
            vulns = query_osv(comp["name"], comp["version"])
            if not vulns and use_vulndb:
                vulns = query_vulndb(comp["name"], comp["version"])
        if not vulns:
            continue
        vuln_rows = []
        kev_hits = []
        for v in vulns:
            cves = _cves_of(v)
            exploited = [c for c in cves if c in kev]
            kev_hits.extend(exploited)
            vuln_rows.append({
                "id": v.get("id"),
                "cves": cves,
                "summary": (v.get("summary") or v.get("details") or "")[:200],
                "known_exploited": bool(exploited),
                "kev_cves": exploited,
            })
        findings.append({
            "component": comp["name"],
            "version": comp["version"],
            "vuln_count": len(vuln_rows),
            "known_exploited": bool(kev_hits),
            "kev_cves": sorted(set(kev_hits)),
            "vulns": vuln_rows,
        })
    # known-exploited first, then by vuln count
    findings.sort(key=lambda f: (not f["known_exploited"], -f["vuln_count"]))
    return findings


def enrich_strings(strings: Iterable[str], **kw) -> List[dict]:
    """Convenience: parse components out of raw strings then enrich them."""
    return enrich_components(parse_components(strings), **kw)


# --------------------------------------------------------------------------- #
# air-gap: pre-resolve OSV so the enrichment runs fully offline
# --------------------------------------------------------------------------- #
def build_offline_index(components: List[Dict[str, str]]) -> Dict[str, List[dict]]:
    """Resolve OSV for components ONLINE into a ``key -> vulns`` map to ship offline."""
    index: Dict[str, List[dict]] = {}
    for comp in components:
        key = f"{comp['name'].lower()} {normalize_version(comp['version'])}"
        index[key] = query_osv(comp["name"], comp["version"])
    return index
