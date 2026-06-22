#!/usr/bin/env bash
# Shell port of the fwxray CORE check: Shannon entropy + magic-signature
# detection over a firmware image. Passive, offline. POSIX tools only
# (od + awk). Emits the same JSON shape as the Python reference.
set -eu

usage() { echo "usage: fwxray.sh <firmware-image>" >&2; exit 2; }
[ $# -ge 1 ] || usage
IMG="$1"
[ -f "$IMG" ] || { echo "error: no such file: $IMG" >&2; exit 2; }

SIZE=$(wc -c < "$IMG" | tr -d ' ')

# One awk pass over the decimal-byte stream computes entropy AND scans for the
# first offset of each known magic signature (labels match the Python catalogue).
od -An -v -tu1 "$IMG" | awk -v size="$SIZE" -v img="$IMG" '
  BEGIN {
    # magic signatures: decimal bytes (space-joined) -> label
    msig[0]="127 69 76 70";            mlab[0]="elf"            # \x7fELF
    msig[1]="31 139 8";                mlab[1]="gzip"           # 1f 8b 08
    msig[2]="104 115 113 115";         mlab[2]="squashfs(le)"   # hsqs
    msig[3]="65 78 68 82 79 73 68 33"; mlab[3]="android_boot"   # ANDROID!
    msig[4]="40 181 47 253";           mlab[4]="zstd"           # 28 b5 2f fd
    msig[5]="66 90 104";               mlab[5]="bzip2"          # BZh
    msig[6]="85 66 73 35";             mlab[6]="ubi"            # UBI#
    NMAGIC = 7
    for (m = 0; m < NMAGIC; m++) mlen[m] = split(msig[m], _t, " ")
    pos = 0
  }
  {
    for (f = 1; f <= NF; f++) {
      b = $f
      hist[b]++
      total++
      buf[pos] = b      # firmware images are small; whole-image buffer is fine
      pos++
    }
  }
  END {
    # --- entropy ---
    ent = 0
    if (total > 0)
      for (b in hist) { p = hist[b] / total; ent -= p * log(p) / log(2) }

    # --- magic scan: first byte-exact match per offset ---
    nhits = 0
    for (off = 0; off < pos; off++) {
      for (m = 0; m < NMAGIC; m++) {
        L = mlen[m]
        if (off + L > pos) continue
        split(msig[m], sp, " ")
        ok = 1
        for (k = 1; k <= L; k++) if (buf[off + k - 1] != sp[k]) { ok = 0; break }
        if (ok) { hoff[nhits] = off; hlab[nhits] = mlab[m]; nhits++ }
      }
    }
    # sort hits by offset
    for (a = 1; a < nhits; a++)
      for (c = a; c > 0 && hoff[c] < hoff[c-1]; c--) {
        t = hoff[c]; hoff[c] = hoff[c-1]; hoff[c-1] = t
        t = hlab[c]; hlab[c] = hlab[c-1]; hlab[c-1] = t
      }
    # emit, collapsing hits within 256 bytes
    out = ""; last = -256
    for (a = 0; a < nhits; a++) {
      if (hoff[a] - last < 256) continue
      last = hoff[a]
      if (out != "") out = out ","
      out = out "{\"label\":\"" hlab[a] "\",\"offset\":" hoff[a] "}"
    }
    printf "{\"tool\":\"fwxray\",\"path\":\"%s\",\"size\":%d,\"entropy\":%.4f,\"sections\":[%s]}\n", img, size, ent, out
  }
'
