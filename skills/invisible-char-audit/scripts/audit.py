#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Entry point for invisible-char-audit.

Reads bytes. Never executes, imports, or renders the target — which matters
here more than in most scanners, because the target is built to be misread.

Exit codes:
  0  nothing at or above the threshold
  1  findings at or above the threshold
  2  target unreadable
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chars as C            # noqa: E402
import detect as D           # noqa: E402
import report                # noqa: E402

VERSION = "1.0.0"

MAX_BYTES = 4 * 1024 * 1024
SKIP_DIRS = {
    "node_modules", ".git", ".svn", "__pycache__", ".venv", "venv", "dist",
    "build", "out", ".next", "target", ".mypy_cache", ".pytest_cache",
    "site-packages", ".tox", "vendor", ".idea", ".vscode",
}
BINARY_EXT = {
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "pdf", "zip", "gz",
    "tar", "7z", "rar", "exe", "dll", "so", "dylib", "class", "jar", "wasm",
    "woff", "woff2", "ttf", "otf", "mp3", "mp4", "mov", "wav", "sqlite", "db",
    "pyc", "o", "a", "lib", "bin",
}


def collect(root, exts):
    files, skipped = [], {"dirs": 0, "binary": 0, "unreadable": 0, "filtered": 0}
    if os.path.isfile(root):
        return [root], skipped
    for dirpath, dirnames, filenames in os.walk(root):
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS or d.startswith(".cache"):
                skipped["dirs"] += 1
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            ext = os.path.splitext(name)[1].lstrip(".").lower()
            if ext in BINARY_EXT:
                skipped["binary"] += 1
                continue
            if exts and ext not in exts:
                skipped["filtered"] += 1
                continue
            files.append(os.path.join(dirpath, name))
    return files, skipped


def scan(root, exts=None):
    exts = set(exts) if exts else None
    files, skipped = collect(root, exts)
    base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
    findings, scanned, total = [], 0, 0
    for path in files:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_BYTES + 1)
        except OSError:
            skipped["unreadable"] += 1
            continue
        if len(raw) > MAX_BYTES:
            skipped["unreadable"] += 1
            continue
        if b"\x00" in raw[:8192] and not raw.startswith(b"\xff\xfe"):
            skipped["binary"] += 1
            continue
        text, enc_finding = D.decode(raw)
        ext = os.path.splitext(path)[1].lstrip(".").lower()
        rel = os.path.relpath(path, base).replace(os.sep, "/") if base else path
        if enc_finding:
            enc_finding["path"] = rel
            enc_finding["line"] = 1
            enc_finding["col"] = 1
            enc_finding["codepoint"] = None
            enc_finding["name"] = None
            enc_finding["char"] = None
            findings.append(enc_finding)
        findings.extend(D.analyze(text, rel, ext))
        scanned += 1
        total += len(raw)
    findings.sort(key=lambda f: (report.ORDER.index(f["severity"]), f["path"], f["line"]))
    # one finding per (id, path, line) is enough to act on
    seen, unique = set(), []
    for f in findings:
        key = (f["id"], f["path"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return {
        "findings": unique, "files_scanned": scanned, "bytes_scanned": total,
        "skipped": skipped,
    }


def explain(cp):
    try:
        n = int(cp.replace("U+", "").replace("u+", ""), 16)
    except ValueError:
        sys.stderr.write("error: expected a codepoint like U+202E\n")
        return 2
    ch = chr(n)
    name = D._name(ch)
    print("%s  %s" % ("U+%04X" % n, name))
    for table, label in ((C.BIDI, "bidi control"), (C.INVISIBLE, "invisible"),
                         (C.SPACES, "space lookalike")):
        if ch in table:
            v = table[ch]
            extra = " — " + v[2] if label == "invisible" else ""
            print("class    %s%s" % (label, extra))
            break
    else:
        if ch in C.VARIATION:
            print("class    variation selector")
        elif ch in C.CONFUSABLES:
            print("class    confusable — reads as '%s'" % C.CONFUSABLES[ch])
        elif C.TAG_FIRST <= n <= C.TAG_LAST:
            print("class    tag character — encodes ASCII %r" % chr(n - C.TAG_BASE))
        else:
            print("class    not in any table")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="audit",
        description="Find characters a reviewer cannot see: bidi overrides, "
                    "zero-width padding, Unicode tag blocks that decode to hidden "
                    "instructions, homoglyphs inside identifiers, and space "
                    "lookalikes that break string comparison.")
    ap.add_argument("target", nargs="?", help="file or directory")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--markdown", metavar="FILE")
    ap.add_argument("--fail-on", default="critical",
                    choices=["critical", "high", "medium", "low", "none"])
    ap.add_argument("--ext", action="append", default=[],
                    metavar="py", help="only scan these extensions, repeatable")
    ap.add_argument("--clean-out", metavar="FILE",
                    help="write a copy with the listed characters removed "
                         "(single target only; never overwrites the input)")
    ap.add_argument("--explain", metavar="U+202E",
                    help="describe one codepoint and exit")
    ap.add_argument("--version", action="version", version="invisible-char-audit " + VERSION)
    args = ap.parse_args(argv)

    if args.explain:
        return explain(args.explain)
    if not args.target:
        ap.print_help()
        return 2
    if not os.path.exists(args.target):
        sys.stderr.write("error: target not found: %s\n" % args.target)
        return 2

    if args.clean_out:
        if not os.path.isfile(args.target):
            sys.stderr.write("error: --clean-out needs a single file target\n")
            return 2
        if os.path.abspath(args.clean_out) == os.path.abspath(args.target):
            sys.stderr.write("error: --clean-out must not overwrite the input\n")
            return 2
        with open(args.target, "rb") as fh:
            text, _ = D.decode(fh.read())
        cleaned, removed = D.strip(text)
        with open(args.clean_out, "w", encoding="utf-8", newline="") as fh:
            fh.write(cleaned)
        print("wrote %s" % args.clean_out)
        if removed:
            for ch, n in removed:
                print("  removed %-10s %-42s x%d" % (D._cp(ch), D._name(ch)[:42], n))
        else:
            print("  nothing to remove")

    res = scan(args.target, args.ext)
    if args.json:
        print(report.render_json(res, args.target))
    else:
        print(report.render_text(res, args.target))
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(report.render_markdown(res, args.target))
        if not args.json:
            print("markdown written to %s" % args.markdown)

    if args.fail_on == "none" or not res["findings"]:
        return 0
    limit = report.ORDER.index(args.fail_on)
    return 1 if any(report.ORDER.index(f["severity"]) <= limit
                    for f in res["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
