"""FWXRAY engine: real firmware diffing with the Python standard library only.

The engine works on raw bytes, so it is independent of any particular OTA
format. It carves a firmware image into sections using well-known magic
signatures (the same idea binwalk uses), computes per-block Shannon entropy,
extracts printable strings, and then diffs two images across all three axes.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Magic signatures. Offset within the image -> (label, signature bytes).
# A small but real catalogue of formats commonly seen inside firmware blobs.
# ---------------------------------------------------------------------------
MAGICS: List[Tuple[bytes, str]] = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x5d\x00\x00", "lzma"),
    (b"PK\x03\x04", "zip"),
    (b"hsqs", "squashfs(le)"),
    (b"sqsh", "squashfs(be)"),
    (b"UBI#", "ubi"),
    (b"\x85\x19", "jffs2"),
    (b"\xd0\x0d\xfe\xed", "dtb(fdt)"),
    (b"\x27\x05\x19\x56", "uimage"),
    (b"ANDROID!", "android_boot"),
    (b"\x7fELF", "elf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"-----BEGIN ", "pem"),
]

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
# key=value or key: value style flags/config tokens.
_FLAG = re.compile(r"^([A-Za-z_][\w.\-]*)\s*[:=]\s*(.*)$")


@dataclass
class Section:
    """A carved region of a firmware image."""

    label: str
    offset: int
    size: int
    sha256: str
    entropy: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FirmwareDiff:
    """Structured result of diffing two firmware images."""

    old_path: str
    new_path: str
    old_size: int
    new_size: int
    old_sha256: str
    new_sha256: str
    identical: bool
    sections_added: List[dict] = field(default_factory=list)
    sections_removed: List[dict] = field(default_factory=list)
    sections_changed: List[dict] = field(default_factory=list)
    flags_added: Dict[str, str] = field(default_factory=dict)
    flags_removed: Dict[str, str] = field(default_factory=dict)
    flags_flipped: Dict[str, dict] = field(default_factory=dict)
    strings_added: List[str] = field(default_factory=list)
    strings_removed: List[str] = field(default_factory=list)
    entropy_shifts: List[dict] = field(default_factory=list)
    overall_entropy_old: float = 0.0
    overall_entropy_new: float = 0.0

    def has_findings(self) -> bool:
        return not self.identical

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). Empty -> 0.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def block_entropy_profile(data: bytes, block: int = 1024) -> List[float]:
    """Per-block entropy profile across the image."""
    if block <= 0:
        raise ValueError("block must be positive")
    return [shannon_entropy(data[i : i + block]) for i in range(0, len(data), block)]


def carve_sections(data: bytes, min_block: int = 256) -> List[Section]:
    """Carve a firmware image into sections by magic signatures.

    Every magic hit starts a new section that runs until the next hit (or EOF).
    Bytes before the first hit become a leading ``raw`` section. If nothing is
    found, the whole image is one ``raw`` section.
    """
    hits: List[Tuple[int, str]] = []
    for sig, label in MAGICS:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            hits.append((idx, label))
            start = idx + 1
    hits.sort(key=lambda h: h[0])

    # Keep boundaries reasonably spaced so a magic appearing inside compressed
    # data does not shred the image into thousands of micro-sections.
    boundaries: List[Tuple[int, str]] = []
    last_off = -min_block
    for off, label in hits:
        if off - last_off >= min_block:
            boundaries.append((off, label))
            last_off = off

    sections: List[Section] = []

    def add(label: str, off: int, end: int) -> None:
        if end <= off:
            return
        chunk = data[off:end]
        sections.append(
            Section(
                label=label,
                offset=off,
                size=len(chunk),
                sha256=hashlib.sha256(chunk).hexdigest(),
                entropy=shannon_entropy(chunk),
            )
        )

    if not boundaries:
        add("raw", 0, len(data))
        return sections

    if boundaries[0][0] > 0:
        add("raw", 0, boundaries[0][0])

    for i, (off, label) in enumerate(boundaries):
        end = boundaries[i + 1][0] if i + 1 < len(boundaries) else len(data)
        add(label, off, end)

    return sections


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract printable ASCII strings of length >= min_len."""
    if min_len < 1:
        raise ValueError("min_len must be >= 1")
    out = []
    for m in _PRINTABLE.finditer(data):
        s = m.group().decode("ascii", "ignore")
        if len(s) >= min_len:
            out.append(s)
    return out


def _parse_flags(strings: List[str]) -> Dict[str, str]:
    """Parse key=value / key: value tokens out of a list of strings."""
    flags: Dict[str, str] = {}
    for s in strings:
        m = _FLAG.match(s.strip())
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        # Avoid swallowing prose: keys should look flag-ish (no spaces).
        if " " in key:
            continue
        flags[key] = val
    return flags


def diff_strings(
    old: bytes, new: bytes, min_len: int = 4
) -> Tuple[List[str], List[str]]:
    """Return (added, removed) printable strings between two images."""
    old_set = set(extract_strings(old, min_len))
    new_set = set(extract_strings(new, min_len))
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    return added, removed


def _diff_flags(
    old_flags: Dict[str, str], new_flags: Dict[str, str]
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, dict]]:
    added = {k: v for k, v in new_flags.items() if k not in old_flags}
    removed = {k: v for k, v in old_flags.items() if k not in new_flags}
    flipped = {
        k: {"old": old_flags[k], "new": new_flags[k]}
        for k in old_flags
        if k in new_flags and old_flags[k] != new_flags[k]
    }
    return added, removed, flipped


def _diff_sections(
    old_secs: List[Section], new_secs: List[Section]
) -> Tuple[List[dict], List[dict], List[dict]]:
    """Match sections by (label, sha) where possible; report add/remove/change.

    A section present (by content sha) in both is unchanged. A label present in
    both but with a different sha is ``changed`` (and we surface its entropy
    delta). Otherwise it is added or removed.
    """
    old_by_sha = {s.sha256: s for s in old_secs}
    new_by_sha = {s.sha256: s for s in new_secs}

    # Group remaining (non-identical) sections by label for change detection.
    old_remaining = [s for s in old_secs if s.sha256 not in new_by_sha]
    new_remaining = [s for s in new_secs if s.sha256 not in old_by_sha]

    changed: List[dict] = []
    added: List[dict] = []
    removed: List[dict] = []

    old_by_label: Dict[str, List[Section]] = {}
    for s in old_remaining:
        old_by_label.setdefault(s.label, []).append(s)

    used_old: set = set()
    for ns in new_remaining:
        bucket = old_by_label.get(ns.label, [])
        match: Optional[Section] = None
        for os_ in bucket:
            if id(os_) in used_old:
                continue
            match = os_
            used_old.add(id(os_))
            break
        if match is not None:
            changed.append(
                {
                    "label": ns.label,
                    "old_offset": match.offset,
                    "new_offset": ns.offset,
                    "old_size": match.size,
                    "new_size": ns.size,
                    "size_delta": ns.size - match.size,
                    "old_sha256": match.sha256,
                    "new_sha256": ns.sha256,
                    "old_entropy": match.entropy,
                    "new_entropy": ns.entropy,
                    "entropy_delta": round(ns.entropy - match.entropy, 4),
                }
            )
        else:
            added.append(ns.to_dict())

    for os_ in old_remaining:
        if id(os_) not in used_old:
            removed.append(os_.to_dict())

    return added, removed, changed


def _entropy_shifts(
    old: bytes, new: bytes, block: int, threshold: float
) -> List[dict]:
    """Block-aligned entropy shifts that exceed ``threshold`` bits/byte."""
    po = block_entropy_profile(old, block)
    pn = block_entropy_profile(new, block)
    shifts: List[dict] = []
    for i in range(min(len(po), len(pn))):
        delta = pn[i] - po[i]
        if abs(delta) >= threshold:
            shifts.append(
                {
                    "block": i,
                    "offset": i * block,
                    "old_entropy": po[i],
                    "new_entropy": pn[i],
                    "delta": round(delta, 4),
                }
            )
    return shifts


def diff_firmware(
    old_path: str,
    new_path: str,
    *,
    block: int = 1024,
    entropy_threshold: float = 1.0,
    min_str_len: int = 4,
    max_strings: int = 200,
) -> FirmwareDiff:
    """Diff two firmware images on disk and return a structured FirmwareDiff."""
    if block <= 0:
        raise ValueError("block must be positive")
    if entropy_threshold < 0:
        raise ValueError("entropy_threshold must be >= 0")
    if min_str_len < 1:
        raise ValueError("min_str_len must be >= 1")
    if max_strings < 0:
        raise ValueError("max_strings must be >= 0")

    with open(old_path, "rb") as f:
        old = f.read()
    with open(new_path, "rb") as f:
        new = f.read()

    old_sha = hashlib.sha256(old).hexdigest()
    new_sha = hashlib.sha256(new).hexdigest()
    identical = old_sha == new_sha

    result = FirmwareDiff(
        old_path=old_path,
        new_path=new_path,
        old_size=len(old),
        new_size=len(new),
        old_sha256=old_sha,
        new_sha256=new_sha,
        identical=identical,
        overall_entropy_old=shannon_entropy(old),
        overall_entropy_new=shannon_entropy(new),
    )
    if identical:
        return result

    old_secs = carve_sections(old)
    new_secs = carve_sections(new)
    added, removed, changed = _diff_sections(old_secs, new_secs)
    result.sections_added = added
    result.sections_removed = removed
    result.sections_changed = changed

    old_strings = extract_strings(old, min_str_len)
    new_strings = extract_strings(new, min_str_len)
    f_added, f_removed, f_flipped = _diff_flags(
        _parse_flags(old_strings), _parse_flags(new_strings)
    )
    result.flags_added = f_added
    result.flags_removed = f_removed
    result.flags_flipped = f_flipped

    s_added, s_removed = diff_strings(old, new, min_str_len)
    result.strings_added = s_added[:max_strings]
    result.strings_removed = s_removed[:max_strings]

    result.entropy_shifts = _entropy_shifts(old, new, block, entropy_threshold)

    return result
