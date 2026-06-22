#!/usr/bin/env bash
# Minimal test harness for the shell port. Builds fixtures, asserts JSON shape.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SH="$HERE/fwxray.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0
check() { if [ "$1" = "$2" ]; then echo "ok   - $3"; else echo "FAIL - $3 (got [$1] want [$2])"; fail=1; fi; }
contains() { case "$1" in *"$2"*) echo "ok   - $3";; *) echo "FAIL - $3 (missing [$2] in $1)"; fail=1;; esac; }

# Fixture 1: ELF magic + zero padding
printf '\x7fELF' > "$TMP/elf.bin"
head -c 300 /dev/zero >> "$TMP/elf.bin"
OUT=$(bash "$SH" "$TMP/elf.bin")
contains "$OUT" '"tool":"fwxray"' "tool field present"
contains "$OUT" '"label":"elf"' "elf magic detected"
contains "$OUT" '"size":304' "size correct"

# Fixture 2: empty-ish uniform buffer -> entropy 0
head -c 64 /dev/zero > "$TMP/zero.bin"
OUT=$(bash "$SH" "$TMP/zero.bin")
contains "$OUT" '"entropy":0.0000' "uniform buffer entropy is 0"

# Fixture 3: gzip magic
printf '\x1f\x8b\x08' > "$TMP/gz.bin"
head -c 300 /dev/zero >> "$TMP/gz.bin"
OUT=$(bash "$SH" "$TMP/gz.bin")
contains "$OUT" '"label":"gzip"' "gzip magic detected"

# Missing file -> exit 2
if bash "$SH" "$TMP/nope.bin" >/dev/null 2>&1; then echo "FAIL - missing file should exit nonzero"; fail=1; else echo "ok   - missing file exits nonzero"; fi

exit $fail
