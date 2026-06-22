#!/usr/bin/env node
// JavaScript port of the fwxray CORE check: Shannon entropy + magic-signature
// carving over a firmware image. Passive, offline. Same JSON shape as Python.
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

const MAGICS = [
  [[0x1f, 0x8b, 0x08], "gzip"],
  [[0x42, 0x5a, 0x68], "bzip2"],          // BZh
  [[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], "xz"],
  [[0x28, 0xb5, 0x2f, 0xfd], "zstd"],
  [[0x50, 0x4b, 0x03, 0x04], "zip"],      // PK\x03\x04
  [[0x68, 0x73, 0x71, 0x73], "squashfs(le)"], // hsqs
  [[0x55, 0x42, 0x49, 0x23], "ubi"],      // UBI#
  [[0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21], "android_boot"], // ANDROID!
  [[0x7f, 0x45, 0x4c, 0x46], "elf"],      // \x7fELF
];

// Shannon entropy in bits/byte (0..8); empty -> 0.
export function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0.0;
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  const n = buf.length;
  let ent = 0.0;
  for (const c of counts) {
    if (c) {
      const p = c / n;
      ent -= p * Math.log2(p);
    }
  }
  return Math.round(ent * 10000) / 10000;
}

function indexOf(buf, sig, from) {
  outer: for (let i = from; i + sig.length <= buf.length; i++) {
    for (let j = 0; j < sig.length; j++) {
      if (buf[i + j] !== sig[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// Carve magic-anchored sections; collapse hits within 256 bytes.
export function carveSections(buf) {
  const hits = [];
  for (const [sig, label] of MAGICS) {
    let start = 0;
    for (;;) {
      const idx = indexOf(buf, sig, start);
      if (idx === -1) break;
      hits.push([idx, label]);
      start = idx + 1;
    }
  }
  hits.sort((a, b) => a[0] - b[0]);
  const out = [];
  let last = -256;
  for (const [off, label] of hits) {
    if (off - last < 256) continue;
    last = off;
    out.push({ label, offset: off });
  }
  return out;
}

export function inspect(path) {
  const buf = readFileSync(path);
  return {
    tool: "fwxray",
    path,
    size: buf.length,
    entropy: shannonEntropy(buf),
    sections: carveSections(buf),
  };
}

const _invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (_invokedDirectly) {
  const path = process.argv[2];
  if (!path) {
    console.error("usage: fwxray <firmware-image>");
    process.exit(2);
  }
  console.log(JSON.stringify(inspect(path), null, 2));
}
