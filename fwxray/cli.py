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
import os
import sys
from typing import List, Optional

from fwxray import TOOL_NAME, TOOL_VERSION
from fwxray.core import FirmwareDiff, diff_firmware


def _fmt_size(d: int) -> str:
    sign = "+" if d > 0 else ""
    return f"{sign}{d}"


def _render_table(r: FirmwareDiff) -> str:
    lines: List[str] = []
    lines.append("FWXRAY firmware changelog")
    lines.append(
        f"  old: {r.old_path}  ({r.old_size} bytes, H={r.overall_entropy_old})"
    )
    lines.append(
        f"  new: {r.new_path}  ({r.new_size} bytes, H={r.overall_entropy_new})"
    )
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
        choices=["table", "json"],
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
    return p


def _validate_args(args: argparse.Namespace) -> Optional[str]:
    """Return an error message string if any argument is invalid, else None."""
    if args.block <= 0:
        return f"--block must be a positive integer, got {args.block}"
    if args.entropy_threshold < 0:
        return (
            f"--entropy-threshold must be >= 0, got {args.entropy_threshold}"
        )
    if args.min_str_len < 1:
        return f"--min-str-len must be >= 1, got {args.min_str_len}"
    for label, path in (("old", args.old), ("new", args.new)):
        if os.path.isdir(path):
            return f"{label!r} path is a directory, not a file: {path!r}"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "diff":
        parser.print_help()
        return 2

    err = _validate_args(args)
    if err:
        print(f"{TOOL_NAME}: error: {err}", file=sys.stderr)
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
    except OSError as e:
        print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"{TOOL_NAME}: error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_render_table(result))

    # CI gate: non-zero when the images differ (there are findings).
    return 1 if result.has_findings() else 0


if __name__ == "__main__":
    sys.exit(main())
