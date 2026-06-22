# Demo 11 — OTA bundles an actively-exploited library

**What happened:** the new firmware image bundles `log4j-core-2.14.1` — squarely
inside the Log4Shell window — together with an ancient `OpenSSL 1.0.2k` and
`lodash 4.17.4`.

**What FWXRAY shows:** the component+version strings appear in `strings_added`.
The data-feed enrichment (`fwxray scan`) parses them, queries **OSV.dev** for
known vulnerabilities, and cross-references every CVE against the **CISA Known
Exploited Vulnerabilities** catalog. `log4j-core 2.14.1` is flagged
**KNOWN-EXPLOITED** for `CVE-2021-44228` (and `CVE-2021-45046`).

## Run it

```bash
python make_images.py

# online (fetches OSV + CISA-KEV, caches them):
fwxray scan old.bin new.bin

# air-gapped (KEV served from the cached snapshot):
COGNIS_FEEDS_CACHE=/media/usb/feeds-snapshot fwxray scan old.bin new.bin --offline
```

The headline finding is `log4j-core 2.14.1 [KNOWN-EXPLOITED] CISA-KEV:
CVE-2021-44228`. `fwxray scan` exits non-zero whenever a known-exploited
component is present, so it gates CI / OTA promotion.

## Fully offline enrichment

`demo_enrich.py` reproduces the finding with **zero network** using the trimmed
OSV/KEV fixtures committed under `tests/fixtures/` — the same data an air-gapped
device would carry in its feed snapshot.
