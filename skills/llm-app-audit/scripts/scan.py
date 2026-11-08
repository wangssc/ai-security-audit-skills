# -*- coding: utf-8 -*-
"""File walker, comment stripper, and rule application.

Everything here is read-only. The scanner opens files, never imports them,
never executes them, and never opens a socket. That is a hard design
constraint, not a limitation to be worked around later: an audit tool that
runs the target inherits the target's risk.

Trade-off made explicit: comments are stripped before matching, because a
comment that says "do not do this" should not be reported as doing it. The
stripper is quote-aware but not a real parser; it errs toward leaving text in
place, which can only cause a missed finding, never a fabricated one.
"""

import os
import re

import detectors
import rules as R

SKIP_DIRS = {
    "node_modules", ".git", ".svn", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "out", ".next", ".nuxt", "coverage", "target",
    ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "site-packages",
    ".tox", "vendor", "bin", "obj", ".gradle", "Pods",
}

SOURCE_EXTS = {
    "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte",
    "md", "txt", "prompt", "yaml", "yml", "json", "toml", "env", "ini",
}

MAX_FILE_BYTES = 1_500_000
MAX_FILES = 4000

# Extensions where comment stripping must not run: JSON has no comments, and
# prompt/markdown files are the instruction itself — stripping them would
# delete the very text we are auditing.
NO_STRIP = {"md", "txt", "prompt", "json", "yaml", "yml", "env", "ini", "toml"}


def strip_comments(text, ext):
    """Remove line comments while respecting quotes. Block comments are left in
    place on purpose: removing them reliably needs a parser, and a half-removed
    block comment is worse than one left alone."""
    if ext in NO_STRIP:
        return text
    if ext in ("py",):
        line_marks = ("#",)
    elif ext in ("html", "vue", "svelte"):
        line_marks = ("//",)
    else:
        line_marks = ("//",)

    out = []
    for line in text.split("\n"):
        cut = len(line)
        quote = None
        esc = False
        i = 0
        while i < len(line):
            ch = line[i]
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'`":
                quote = ch
            else:
                for m in line_marks:
                    if line.startswith(m, i):
                        # Only a column-0 marker is kept (shebang, encoding cookie).
                        # An indented comment must be cut: a comment saying
                        # "no tenant filter here" would otherwise read as evidence
                        # that a filter exists, and silence the finding.
                        if i == 0:
                            break
                        cut = i
                        break
                if cut != len(line):
                    break
            i += 1
        out.append(line[:cut])
    return "\n".join(out)


def read_text(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_FILE_BYTES:
        raw = raw[:MAX_FILE_BYTES]
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


class Ctx(object):
    __slots__ = ("path", "rel", "ext", "text", "code", "lines")

    def __init__(self, path, rel, ext, text, code):
        self.path = path
        self.rel = rel
        self.ext = ext
        self.text = text
        self.code = code
        self.lines = code.split("\n")


def collect(root):
    """Yield Ctx for every readable source file under root."""
    ctxs = []
    skipped = {"dirs": 0, "files": 0, "unreadable": 0, "too_many": 0}
    root = os.path.abspath(root)

    if os.path.isfile(root):
        ext = os.path.splitext(root)[1].lstrip(".").lower()
        text = read_text(root)
        if text is None:
            skipped["unreadable"] = 1
            return ctxs, skipped
        ctxs.append(Ctx(root, os.path.basename(root), ext, text,
                        strip_comments(text, ext)))
        return ctxs, skipped

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
            if ext not in SOURCE_EXTS:
                skipped["files"] += 1
                continue
            if len(ctxs) >= MAX_FILES:
                skipped["too_many"] += 1
                continue
            full = os.path.join(dirpath, name)
            text = read_text(full)
            if text is None:
                skipped["unreadable"] += 1
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            ctxs.append(Ctx(full, rel, ext, text, strip_comments(text, ext)))
    return ctxs, skipped


def _window(ctx, idx, radius=15):
    lo = max(0, idx - radius)
    hi = min(len(ctx.lines), idx + radius + 1)
    return "\n".join(ctx.lines[lo:hi])


def _vetoed(ctx, rule, idx):
    veto = rule.get("veto")
    if not veto:
        return False
    try:
        pat = re.compile(veto, re.IGNORECASE)
    except re.error:
        return False
    if pat.search(_window(ctx, idx)):
        return True
    # An import or a config line anywhere in the file also counts as a guard:
    # a sanitizer imported at the top is in force at the call site.
    for line in ctx.lines:
        if re.match(r"\s*(import|from|require\(|const .*=\s*require|#include)", line):
            if pat.search(line):
                return True
    return False


def _snippet(line, limit=200):
    s = line.strip()
    return s[:limit] + ("..." if len(s) > limit else "")


def apply_file_rules(ctxs):
    findings = []
    for ctx in ctxs:
        file_has_model = bool(re.search(R.MODEL_CALL, ctx.code, re.IGNORECASE))
        for rule in R.FILE_RULES:
            if ctx.ext not in rule["exts"]:
                continue
            if rule.get("require_model_in_file") and not file_has_model:
                continue
            try:
                pat = re.compile(rule["pattern"], re.IGNORECASE)
            except re.error:
                continue
            need = rule.get("need")
            if need:
                try:
                    if not re.search(need, ctx.code + "\n" + ctx.text, re.IGNORECASE):
                        continue
                except re.error:
                    pass

            hits = 0
            for idx, line in enumerate(ctx.lines):
                if not line.strip():
                    continue
                if not pat.search(line):
                    continue
                if _vetoed(ctx, rule, idx):
                    continue
                findings.append({
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "owasp": rule["owasp"],
                    "why": rule["why"],
                    "fix": rule["fix"],
                    "path": ctx.rel,
                    "line": idx + 1,
                    "snippet": _snippet(line),
                    "kind": "pattern",
                })
                hits += 1
                if hits >= rule["max_per_file"]:
                    break
    return findings


def apply_file_absence_rules(ctxs):
    findings = []
    for ctx in ctxs:
        for rule in R.FILE_ABSENCE_RULES:
            if not re.search(rule["requires"], ctx.code, re.IGNORECASE):
                continue
            if re.search(rule["absent"], ctx.code, re.IGNORECASE):
                continue
            # Point at the first real call site so the reader has somewhere to look.
            line_no, snip = 1, ""
            try:
                m = re.search(rule["requires"], ctx.code, re.IGNORECASE)
                if m:
                    line_no = ctx.code[: m.start()].count("\n") + 1
                    snip = _snippet(ctx.lines[line_no - 1]) if ctx.lines else ""
            except re.error:
                pass
            findings.append({
                "id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "owasp": rule["owasp"],
                "why": rule["why"],
                "fix": rule["fix"],
                "path": ctx.rel,
                "line": line_no,
                "snippet": snip,
                "kind": "absence",
            })
    return findings


def apply_project_rules(ctxs):
    findings = []
    if not ctxs:
        return findings
    # Paths matter for absence rules: an evals/ directory or a file called
    # golden.json is evidence of a practice even when the word never appears in
    # the source. Checking contents alone would report it as missing.
    blob = "\n".join(c.text for c in ctxs)
    paths = "\n".join(c.rel for c in ctxs)
    if not re.search(R.MODEL_CALL, blob, re.IGNORECASE):
        return findings
    for rule in R.PROJECT_RULES:
        if re.search(rule["absent"], blob, re.IGNORECASE):
            continue
        if re.search(rule["absent"], paths, re.IGNORECASE):
            continue
        findings.append({
            "id": rule["id"],
            "severity": rule["severity"],
            "title": rule["title"],
            "owasp": rule["owasp"],
            "why": rule["why"],
            "fix": rule["fix"],
            "path": "(project)",
            "line": 0,
            "snippet": "",
            "kind": "absence",
        })
    return findings


def apply_custom_detectors(ctxs, has_model):
    findings = []
    for ctx in ctxs:
        for detector in detectors.CUSTOM_DETECTORS:
            try:
                if detector is detectors.detect_retrieval_filter:
                    findings.extend(detector(ctx, project_has_model=has_model))
                else:
                    findings.extend(detector(ctx))
            except Exception:  # noqa: BLE001 - a broken detector must not abort the scan
                continue
    return findings


def scan(root):
    ctxs, skipped = collect(root)
    has_model = bool(re.search(R.MODEL_CALL,
                               "\n".join(c.text for c in ctxs),
                               re.IGNORECASE)) if ctxs else False
    findings = []
    findings += apply_file_rules(ctxs)
    findings += apply_custom_detectors(ctxs, has_model)
    findings += apply_file_absence_rules(ctxs)
    findings += apply_project_rules(ctxs)
    findings.sort(key=lambda f: (R.SEVERITY_ORDER.index(f["severity"]), f["id"], f["path"]))
    # Same rule firing on the same file three times is one problem, not three.
    seen, unique = set(), []
    for f in findings:
        key = (f["id"], f["path"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return {
        "ctxs": ctxs,
        "skipped": skipped,
        "findings": unique,
        "files_scanned": len(ctxs),
        "bytes_scanned": sum(len(c.text.encode("utf-8", "ignore")) for c in ctxs),
        "has_model_call": has_model,
    }
