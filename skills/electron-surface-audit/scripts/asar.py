"""Read Electron ASAR archives without unpacking them.

Layout: 8-byte pickle header (payload size, then JSON size), the JSON directory
header, then file bytes addressed by decimal string offsets. Some tooling rewrites
the pickle header, so the offset of the JSON is located by its opening token
instead of being assumed to be 16.
"""

from __future__ import annotations

import json
import os
import struct
from typing import Any, Iterator

HEADER_TOKEN = b'{"files"'


def _locate_header(buf: bytes) -> tuple[int, int] | None:
    """Return (json_start, json_len) or None.

    The pickle prefix is 8 bytes in a canonical archive, but repacked archives in
    the wild carry extra bytes before it. Anchoring on `{"files"` and then walking
    the brace depth is what survives both.
    """
    idx = buf.find(HEADER_TOKEN, 0, 1 << 20)
    if idx < 0:
        return None

    depth = 0
    in_str = False
    esc = False
    for i in range(idx, len(buf)):
        c = buf[i]
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:  # backslash
                esc = True
            elif c == 0x22:  # quote
                in_str = False
            continue
        if c == 0x22:
            in_str = True
        elif c == 0x7B:  # {
            depth += 1
        elif c == 0x7D:  # }
            depth -= 1
            if depth == 0:
                return idx, i - idx + 1
    return None


def parse_asar(path: str) -> dict[str, Any]:
    with open(path, "rb") as fh:
        buf = fh.read()

    loc = _locate_header(buf)
    if not loc:
        return {"ok": False, "reason": "no ASAR header found (not an asar, or the archive is corrupt)"}

    json_start, json_len = loc
    try:
        header = json.loads(buf[json_start : json_start + json_len].decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - report whatever the parser said
        return {"ok": False, "reason": f"ASAR header is not valid JSON: {exc}"}

    # Pickle layout ahead of the JSON is
    #   [u32 payload size][u32 header size][JSON][padding to 4-byte boundary]
    # and file data starts after the padding, not after the JSON text. Reading the
    # declared header size at json_start-4 is what keeps member offsets aligned on
    # archives whose JSON length is not a multiple of four.
    declared = None
    if json_start >= 4:
        try:
            declared = struct.unpack_from("<I", buf, json_start - 4)[0]
        except struct.error:
            declared = None

    # Traceback guard: a declared size that cannot possibly be right means we are
    # looking at a rewritten header, so fall back to the measured JSON length.
    if declared is None or declared < json_len or declared > json_len + 64:
        declared = json_len

    data_offset = json_start + declared
    files = list(_walk(header.get("files") or {}, ""))

    return {
        "ok": True,
        "path": path,
        "size": len(buf),
        "json_start": json_start,
        "json_len": json_len,
        "data_offset": data_offset,
        "declared_header_size": declared,
        "header_padding": declared - json_len,
        "files": files,
        "file_count": len(files),
    }


def _walk(node: dict, prefix: str) -> Iterator[dict[str, Any]]:
    for name, meta in node.items():
        path = f"{prefix}/{name}" if prefix else name
        if isinstance(meta, dict) and "files" in meta:
            yield from _walk(meta["files"], path)
        elif isinstance(meta, dict):
            size = meta.get("size")
            offset = meta.get("offset")
            yield {
                "path": path,
                "size": int(size) if size is not None else None,
                "offset": int(offset) if offset is not None else None,
                "unpacked": meta.get("unpacked", False),
            }


def find_asar(binary_path: str) -> str | None:
    """Best-effort: locate the app archive relative to an Electron executable.

    Two layouts exist in the wild: `resources/app.asar` and `resources/app/<name>.asar`
    (Typora ships the second). Both are checked, and the app-dir form is accepted
    when it holds exactly one archive so an unrelated bundle cannot be picked up by
    accident.
    """
    import glob

    base = os.path.dirname(os.path.abspath(binary_path))
    roots = [
        os.path.join(base, "resources"),                              # Windows / Linux
        os.path.join(base, "..", "Resources"),                        # macOS Contents/MacOS/x
        os.path.join(base, "..", "..", "Resources"),                  # one level deeper
    ]
    for root in roots:
        root = os.path.normpath(root)
        direct = os.path.join(root, "app.asar")
        if os.path.isfile(direct):
            return direct
        # A backup archive is still the real application code; auditing it beats
        # reporting "no application found" on an install that moved the live file.
        backup = os.path.join(root, "app.asar.bak")
        if os.path.isfile(backup):
            return backup
        appdir = os.path.join(root, "app")
        if os.path.isdir(appdir):
            found = sorted(glob.glob(os.path.join(appdir, "*.asar")))
            if len(found) == 1:
                return found[0]
            if found:
                # Several archives: prefer the one that is not a library bundle.
                for f in found:
                    if "asar" in os.path.basename(f).lower() and "lib" not in os.path.basename(f).lower():
                        return f
                return found[0]
    return None


def read_file(asar: dict[str, Any], rel_path: str, limit: int = 4 << 20) -> bytes | None:
    """Read one member out of a parsed archive."""
    target = None
    for f in asar.get("files", []):
        if f["path"] == rel_path:
            target = f
            break
    if not target or target.get("offset") is None:
        return None
    start = asar["data_offset"] + target["offset"]
    size = target.get("size") or 0
    if size > limit:
        size = limit
    with open(asar["path"], "rb") as fh:
        fh.seek(start)
        return fh.read(size)
