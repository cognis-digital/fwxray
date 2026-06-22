"""FWXRAY command-line interface.

Examples
--------
  # Human-readable changelog of what an OTA touched
  fwxray diff old.bin new.bin

  # JSON for CI / piping (exit code 1 when the images differ)
  fwxray diff old.bin new.bin --format json > changelog.json

  # Tune entropy-shift sensitivity and block size
  fwxray diff v1.bin v2.bin --block 2048 --entropy-threshold 0.5
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from fwxray import TOOL_NAME, TOOL_VERSION
from fwxray.core import FirmwareDiff, diff_firmware, to_sarif
from fwxray import datafeeds, feeds as feeds_mod


def _fmt_size(d: int) -> str:
    sign = "+" if d > 0 else ""
    return f"{sign}{d}"


def _render_table(r: FirmwareDiff) -> str:
    lines: List[str] = []
    lines.append(f"FWXRAY firmware changelog")
    lines.append(f"  old: {r.old_path}  ({r.old_size} bytes, H={r.overall_entropy_old})")
    lines.append(f"  new: {r.new_path}  ({r.new_size} bytes, H={r.overall_entropy_new})")
    lines.append(f"  size delta: {_fmt_size(r.new_size - r.old_size)} bytes")
    if r.identical:
        lines.append("")
        lines.append("  IDENTICAL - the two images are byte-for-byte equal.")
        return "\n".join(lines)

    lines.append("")
    lines.append("== Sections ==")
    if r.sections_changed:
        for s in r.sections_changed:
            lines.append(
                f"  ~ {s['label']:<14} size {_fmt_size(s['size_delta'])}"
                f"  entropy {_fmt_size_f(s['entropy_delta'])}"
                f"  @0x{s['new_offset']:x}"
            )
    for s in r.sections_added:
        lines.append(f"  + {s['label']:<14} {s['size']} bytes @0x{s['offset']:x}")
    for s in r.sections_removed:
        lines.append(f"  - {s['label']:<14} {s['size']} bytes @0x{s['offset']:x}")
    if not (r.sections_changed or r.sections_added or r.sections_removed):
        lines.append("  (no section-level changes)")

    lines.append("")
    lines.append("== Flags / config ==")
    for k, v in r.flags_flipped.items():
        lines.append(f"  ~ {k}: {v['old']!r} -> {v['new']!r}")
    for k, v in r.flags_added.items():
        lines.append(f"  + {k}: {v!r}")
    for k, v in r.flags_removed.items():
        lines.append(f"  - {k}: {v!r}")
    if not (r.flags_flipped or r.flags_added or r.flags_removed):
        lines.append("  (no flag changes)")

    lines.append("")
    lines.append("== Entropy shifts ==")
    if r.entropy_shifts:
        for e in r.entropy_shifts:
            lines.append(
                f"  @0x{e['offset']:x}  {e['old_entropy']} -> {e['new_entropy']}"
                f"  ({_fmt_size_f(e['delta'])} bits/byte)"
            )
    else:
        lines.append("  (no significant entropy shifts)")

    lines.append("")
    lines.append("== Strings ==")
    lines.append(
        f"  +{len(r.strings_added)} added / -{len(r.strings_removed)} removed"
    )
    for s in r.strings_added[:10]:
        lines.append(f"    + {s}")
    for s in r.strings_removed[:10]:
        lines.append(f"    - {s}")

    return "\n".join(lines)


def _fmt_size_f(d: float) -> str:
    return f"+{d}" if d > 0 else f"{d}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "X-ray two firmware images and produce a human-readable changelog "
            "of what an OTA touched: changed sections, flipped flags, and "
            "entropy shifts."
        ),
        epilog=(
            "examples:\n"
            "  fwxray diff old.bin new.bin\n"
            "  fwxray diff old.bin new.bin --format json > changelog.json\n"
            "  fwxray diff v1.bin v2.bin --block 2048 --entropy-threshold 0.5\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    d = sub.add_parser(
        "diff",
        help="diff two firmware images",
        description="Diff two firmware images and report the changes.",
    )
    d.add_argument("old", help="path to the old/baseline firmware image")
    d.add_argument("new", help="path to the new/updated firmware image")
    d.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="output format (default: table)",
    )
    d.add_argument(
        "--block",
        type=int,
        default=1024,
        help="entropy block size in bytes (default: 1024)",
    )
    d.add_argument(
        "--entropy-threshold",
        type=float,
        default=1.0,
        help="min |delta| bits/byte to report an entropy shift (default: 1.0)",
    )
    d.add_argument(
        "--min-str-len",
        type=int,
        default=4,
        help="minimum printable string length (default: 4)",
    )

    # ---- data-feed enrichment -------------------------------------------- #
    f = sub.add_parser(
        "feeds",
        help="manage the OSV / CISA-KEV data feeds (edge/air-gap)",
        description=(
            "Edge/air-gap-deployable ingestion of the two authoritative feeds "
            "fwxray consumes: osv (OSV.dev vuln query) and cisa-kev (CISA Known "
            "Exploited Vulnerabilities). Feeds are fetched keyless over HTTPS, "
            "cached to COGNIS_FEEDS_CACHE, and re-served with --offline."
        ),
    )
    fsub = f.add_subparsers(dest="feeds_cmd", metavar="SUBCOMMAND")
    fsub.add_parser("list", help="list the feeds this repo consumes")
    fu = fsub.add_parser("update", help="fetch + cache a feed (online)")
    fu.add_argument("feed", choices=list(feeds_mod.FEED_IDS), help="feed id")
    fg = fsub.add_parser("get", help="print a cached/fetched feed")
    fg.add_argument("feed", choices=list(feeds_mod.FEED_IDS), help="feed id")
    fg.add_argument("--offline", action="store_true",
                    help="serve from cache only; never touch the network")

    s = sub.add_parser(
        "scan",
        help="diff two firmware images and enrich added components via OSV/KEV",
        description=(
            "Diff two firmware images, parse component+version tokens out of the "
            "newly-added strings, query OSV for known vulnerabilities, and flag "
            "any CVE on the CISA-KEV known-exploited list."
        ),
    )
    s.add_argument("old", help="path to the old/baseline firmware image")
    s.add_argument("new", help="path to the new/updated firmware image")
    s.add_argument("--offline", action="store_true",
                   help="enrich from cached feeds only (KEV from cache; OSV skipped)")
    s.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")
    s.add_argument("--min-str-len", type=int, default=4,
                   help="minimum printable string length (default: 4)")
    return p


def _cmd_feeds(args) -> int:
    sub = getattr(args, "feeds_cmd", None)
    if sub == "list":
        catalog = datafeeds.load_catalog()
        index = {f["id"]: f for f in catalog.get("feeds", [])}
        for fid in feeds_mod.FEED_IDS:
            f = index.get(fid, {})
            age = datafeeds.cached_age_hours(fid)
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {fid:10} [{fresh:>10}]  {f.get('name', '?')}")
            if f.get("url"):
                print(f"             {f['url']}")
        return 0
    if sub == "update":
        path = datafeeds.update(args.feed)
        print(f"updated {args.feed} -> {path} ({path.stat().st_size} bytes)")
        return 0
    if sub == "get":
        try:
            data = datafeeds.get(args.feed, offline=args.offline)
        except (FileNotFoundError, ConnectionError, KeyError) as e:
            print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
            return 2
        out = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
        print(out[:4000])
        return 0
    print("usage: fwxray feeds {list|update|get}", file=sys.stderr)
    return 2


def _render_scan(diff: FirmwareDiff, findings: List[dict]) -> str:
    lines = ["FWXRAY component vulnerability scan",
             f"  old: {diff.old_path}", f"  new: {diff.new_path}",
             f"  added strings scanned: {len(diff.strings_added)}", ""]
    if not findings:
        lines.append("  No vulnerable components matched in the added strings.")
        return "\n".join(lines)
    kev = sum(1 for f in findings if f["known_exploited"])
    lines.append(f"== {len(findings)} vulnerable component(s), {kev} with KNOWN-EXPLOITED CVEs ==")
    for f in findings:
        flag = "  [KNOWN-EXPLOITED]" if f["known_exploited"] else ""
        lines.append(f"  {f['component']} {f['version']}  ({f['vuln_count']} vuln){flag}")
        if f["kev_cves"]:
            lines.append(f"      CISA-KEV: {', '.join(f['kev_cves'])}")
        for v in f["vulns"][:5]:
            mark = "!" if v["known_exploited"] else "-"
            cves = ", ".join(v["cves"]) or v["id"]
            lines.append(f"      {mark} {cves}: {v['summary']}")
    return "\n".join(lines)


def _cmd_scan(args) -> int:
    try:
        diff = diff_firmware(args.old, args.new, min_str_len=args.min_str_len)
    except (FileNotFoundError, ValueError) as e:
        print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2
    try:
        findings = feeds_mod.enrich_strings(diff.strings_added, offline=args.offline)
    except (FileNotFoundError, ConnectionError) as e:
        print(f"{TOOL_NAME}: feed error: {e}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"old": diff.old_path, "new": diff.new_path,
                          "findings": findings}, indent=2))
    else:
        print(_render_scan(diff, findings))
    # CI gate: non-zero when a known-exploited component is present.
    return 1 if any(f["known_exploited"] for f in findings) else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "feeds":
        return _cmd_feeds(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command != "diff":
        parser.print_help()
        return 2

    try:
        result = diff_firmware(
            args.old,
            args.new,
            block=args.block,
            entropy_threshold=args.entropy_threshold,
            min_str_len=args.min_str_len,
        )
    except FileNotFoundError as e:
        print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(result), indent=2))
    else:
        print(_render_table(result))

    # CI gate: non-zero when the images differ (there are findings).
    return 1 if result.has_findings() else 0


if __name__ == "__main__":
    sys.exit(main())
