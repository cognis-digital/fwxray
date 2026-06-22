"""fwxray.active — AUTHORIZED-USE-ONLY live device acquisition.

PASSIVE is the default: fwxray normally works on firmware images you already
have on disk (``diff``/``scan``/``inspect``). Nothing in passive mode touches a
device or a network.

ACTIVE mode reads a live firmware image *off a device or interface you own* — a
mounted MTD/flash partition, a block device, or a local capture endpoint — so
you can diff a fielded unit against a golden image. Pulling bytes off a device
is an intrusive operation, so this module is **locked down by construction**:

  * **OFF by default.** The ``pull`` CLI command refuses to run unless the caller
    passes ``--authorized``.
  * **Scope-enforced.** The source path/endpoint must match an explicit
    allowlist (``--allow`` entries or ``FWXRAY_DEVICE_ALLOWLIST``). A source not
    in scope is refused — never silently read.
  * **Rate-limited.** Reads are throttled to ``--max-bytes-per-sec`` so a pull
    can't hammer a device; a hard ``--max-bytes`` ceiling bounds the total.
  * **Loud banner.** Every authorized pull prints an authorized-use-only banner
    naming the source and the operator.

There is intentionally **no remote/network target** here: fwxray only ever reads
local devices/interfaces the operator physically controls. Tests exercise this
path against bundled fixture "device" files and an in-memory clock — never a real
device, never a network host.

Defensive / authorized-use only. Reading firmware off hardware you do not own or
are not authorized to test may be illegal. You are responsible for your scope.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

BANNER = (
    "=" * 70 + "\n"
    "  FWXRAY ACTIVE ACQUISITION  --  AUTHORIZED USE ONLY\n"
    "  You are reading firmware off a live device/interface.\n"
    "  Only operate against hardware you OWN or are explicitly AUTHORIZED\n"
    "  to test. Acquisition is logged. Scope is enforced.\n"
    + "=" * 70
)

# Default read chunk; small enough that the rate limiter stays responsive.
_CHUNK = 64 * 1024


class AuthorizationError(PermissionError):
    """Raised when active acquisition is attempted without authorization."""


class ScopeError(PermissionError):
    """Raised when the source is not in the authorized allowlist."""


@dataclass
class AcquisitionPolicy:
    """The gate every active pull must pass.

    Nothing reads a device until :meth:`authorize` returns cleanly. The policy
    is deliberately fail-closed: an empty allowlist authorizes *nothing*.
    """

    authorized: bool = False
    allowlist: List[str] = field(default_factory=list)
    max_bytes: int = 64 * 1024 * 1024          # 64 MiB hard ceiling
    max_bytes_per_sec: int = 8 * 1024 * 1024    # 8 MiB/s throttle (0 = unlimited)

    @classmethod
    def from_env_and_args(
        cls,
        *,
        authorized: bool,
        allow: Optional[List[str]] = None,
        max_bytes: Optional[int] = None,
        max_bytes_per_sec: Optional[int] = None,
    ) -> "AcquisitionPolicy":
        """Build a policy from CLI args, merging ``FWXRAY_DEVICE_ALLOWLIST``."""
        entries: List[str] = list(allow or [])
        env = os.environ.get("FWXRAY_DEVICE_ALLOWLIST", "")
        for part in env.split(os.pathsep):
            part = part.strip()
            if part:
                entries.append(part)
        kwargs = {"authorized": bool(authorized), "allowlist": entries}
        if max_bytes is not None:
            kwargs["max_bytes"] = int(max_bytes)
        if max_bytes_per_sec is not None:
            kwargs["max_bytes_per_sec"] = int(max_bytes_per_sec)
        return cls(**kwargs)

    def in_scope(self, source: str) -> bool:
        """True iff ``source`` matches an allowlist entry (glob or exact path)."""
        if not self.allowlist:
            return False
        src = os.path.normpath(source)
        for entry in self.allowlist:
            e = entry.strip()
            if not e:
                continue
            if fnmatch.fnmatch(src, os.path.normpath(e)) or fnmatch.fnmatch(source, e):
                return True
            # exact path match (after normalization)
            if src == os.path.normpath(e):
                return True
        return False

    def authorize(self, source: str) -> None:
        """Fail-closed gate. Raises unless ``source`` is authorized + in scope."""
        if not self.authorized:
            raise AuthorizationError(
                "active acquisition is OFF by default; pass --authorized to "
                "confirm you are authorized to read this device"
            )
        if not self.allowlist:
            raise ScopeError(
                "no device allowlist provided; pass --allow <path-or-glob> "
                "(or set FWXRAY_DEVICE_ALLOWLIST). Empty scope authorizes nothing"
            )
        if not self.in_scope(source):
            raise ScopeError(
                f"source {source!r} is not in the authorized allowlist "
                f"{self.allowlist!r}; refusing to read out-of-scope device"
            )


@dataclass
class AcquisitionResult:
    """Outcome of a live pull."""

    source: str
    bytes_read: int
    sha256: str
    truncated: bool
    elapsed_s: float
    out_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "bytes_read": self.bytes_read,
            "sha256": self.sha256,
            "truncated": self.truncated,
            "elapsed_s": round(self.elapsed_s, 4),
            "out_path": self.out_path,
        }


def _rate_limit(
    written: int,
    started: float,
    max_bps: int,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> None:
    """Throttle so cumulative throughput stays under ``max_bps`` bytes/sec."""
    if max_bps <= 0:
        return
    target = written / max_bps
    elapsed = clock() - started
    if target > elapsed:
        sleep(target - elapsed)


def acquire(
    source: str,
    policy: AcquisitionPolicy,
    *,
    out_path: Optional[str] = None,
    opener: Optional[Callable[[str], object]] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    chunk: int = _CHUNK,
) -> AcquisitionResult:
    """Read a live firmware image from ``source`` under ``policy``.

    The policy gate runs FIRST; not a single byte is read until it passes.
    ``opener`` defaults to opening ``source`` as a binary file (a device node,
    block device, or mounted partition appears as a file on POSIX). Tests inject
    a fixture opener + fake clock so this path never touches real hardware.

    Bytes are streamed (never fully buffered), throttled by the policy's rate
    limit, and truncated at the policy's ``max_bytes`` ceiling.
    """
    policy.authorize(source)  # fail-closed; raises if not authorized/in-scope

    _open = opener or (lambda s: open(s, "rb"))
    digest = hashlib.sha256()
    started = clock()
    total = 0
    truncated = False
    sink = open(out_path, "wb") if out_path else None
    try:
        fh = _open(source)
        try:
            while True:
                want = chunk
                if policy.max_bytes:
                    remaining = policy.max_bytes - total
                    if remaining <= 0:
                        truncated = True
                        break
                    want = min(chunk, remaining)
                buf = fh.read(want)
                if not buf:
                    break
                total += len(buf)
                digest.update(buf)
                if sink is not None:
                    sink.write(buf)
                _rate_limit(total, started, policy.max_bytes_per_sec,
                            clock=clock, sleep=sleep)
        finally:
            close = getattr(fh, "close", None)
            if callable(close):
                close()
    finally:
        if sink is not None:
            sink.close()

    return AcquisitionResult(
        source=source,
        bytes_read=total,
        sha256=digest.hexdigest(),
        truncated=truncated,
        elapsed_s=clock() - started,
        out_path=out_path,
    )
