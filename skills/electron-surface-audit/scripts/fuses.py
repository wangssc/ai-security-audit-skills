"""Locate and decode the Electron fuse table inside an arbitrary binary."""

from __future__ import annotations

import mmap
import os
from typing import Any

from fuse_map import FUSE_BY_ID, FUSES, SENTINEL, STATE_NAME


def _decode_table(buf: bytes, start: int) -> dict[str, Any] | None:
    """Decode one candidate table at `start`. Returns None if the shape is wrong.

    Wire format is a positional array, not id/state pairs: after the sentinel and
    two header bytes come exactly `count` single-byte states, one per fuse id in
    ascending order (id 0 first). Verified against a shipped Electron 3x binary:
    `01 09 31 30 31 31 30 30 30 31 31` decodes to RunAsNode=enabled,
    CookieEncryption=disabled, ... which matches what the runtime reports.
    """
    pos = start + len(SENTINEL)
    if pos + 2 > len(buf):
        return None
    version = buf[pos]
    count = buf[pos + 1]
    # A real table has 1..32 entries and a small wire version. Anything else is a
    # coincidental match inside a string pool or a compressed section.
    if version == 0 or version > 4 or count == 0 or count > 32:
        return None
    if pos + 2 + count > len(buf):
        return None

    entries = {}
    for fid in range(count):
        state = buf[pos + 2 + fid]
        if state not in STATE_NAME:  # '0' / '1' / '2' only
            return None
        entries[fid] = state

    return {"offset": start, "version": version, "count": count, "raw": entries}


def scan_fuses(path: str) -> dict[str, Any]:
    """Scan the whole file for fuse sentinels.

    Chromium builds embed several string-pool copies of the sentinel; only the one
    followed by a well-formed table is real, so we validate the shape of every hit
    and keep all that pass. Fat Mach-O binaries can legitimately yield more than
    one (one per architecture slice).
    """
    size = os.path.getsize(path)
    if size == 0:
        return {"found": False, "tables": [], "reason": "empty file"}

    with open(path, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            tables = []
            start = 0
            while True:
                idx = mm.find(SENTINEL, start)
                if idx < 0:
                    break
                start = idx + 1
                # Copy just enough bytes for a maximal table instead of slicing the whole map.
                chunk_end = min(len(mm), idx + len(SENTINEL) + 2 + 2 * 32)
                decoded = _decode_table(mm[idx:chunk_end], 0)
                if decoded:
                    decoded["offset"] += idx
                    tables.append(decoded)

    if not tables:
        return {
            "found": False,
            "tables": [],
            "reason": "no valid fuse table (pre-fuse Electron build, or the sentinel was stripped)",
        }

    # Prefer the table with the most entries -- that is the one the runtime reads.
    tables.sort(key=lambda t: t["count"], reverse=True)
    return {"found": True, "tables": tables, "primary": tables[0]}


def describe(scan: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn the raw table into a scored, human-readable list."""
    if not scan.get("found"):
        return []

    raw = scan["primary"]["raw"]
    out = []
    for spec in FUSES:
        state_byte = raw.get(spec["id"])
        if state_byte is None:
            continue
        state = STATE_NAME[state_byte]
        risky = state != spec["safe_state"]
        out.append(
            {
                "id": spec["id"],
                "key": spec["key"],
                "label": spec["label"],
                "state": state,
                "safe_state": spec["safe_state"],
                "risky": risky,
                "severity": spec["severity"] if risky else "ok",
                "why": spec["why"] if risky else "",
                "fix": spec["fix"],
            }
        )

    known = {s["id"] for s in FUSES}
    for fid, state_byte in raw.items():
        if fid in known:
            continue
        out.append(
            {
                "id": fid,
                "key": f"UnknownFuse{fid}",
                "label": f"Unrecognised fuse #{fid}",
                "state": STATE_NAME[state_byte],
                "safe_state": "unknown",
                "risky": False,
                "severity": "unknown",
                "why": "This Electron version ships a fuse this auditor does not know about yet.",
                "fix": "check the Electron release notes for this fuse id",
            }
        )
    return out
