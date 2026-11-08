# -*- coding: utf-8 -*-
"""Scoring and rendering.

Two decisions worth defending.

1. The score is capped at 60 when any critical finding exists. A small codebase
   with one live injection path is not "mostly fine" — severity is not a
   fraction of line count.

2. "not assessed" is a real outcome, and it is not 100. If no model call was
   found in the tree, the tool found nothing to audit, which is different from
   finding nothing wrong. Those two must never print the same number.
"""

import json
import math

import rules as R

GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def score(findings, has_model_call):
    if not has_model_call:
        return None, "not assessed"
    penalty = sum(R.SEVERITY_WEIGHT[f["severity"]] for f in findings)
    raw = round(100 * math.exp(-penalty / 70.0))
    if any(f["severity"] == "critical" for f in findings):
        raw = min(raw, 60)
    raw = max(0, min(100, raw))
    for floor, letter in GRADES:
        if raw >= floor:
            return raw, letter
    return raw, "F"


def counts(findings):
    out = {}
    for sev in R.SEVERITY_ORDER:
        out[sev] = sum(1 for f in findings if f["severity"] == sev)
    return out


def _bar(n, total, width=24):
    if not total:
        return ""
    filled = int(round(width * n / float(total)))
    return "#" * filled + "." * (width - filled)


def render_text(res, target):
    findings = res["findings"]
    value, grade = score(findings, res["has_model_call"])
    by_sev = counts(findings)
    lines = []

    lines.append("target   %s" % target)
    lines.append("scanned  %d files, %.1f KB" % (
        res["files_scanned"], res["bytes_scanned"] / 1024.0))
    lines.append("")

    if value is None:
        lines.append("score    not assessed (no model call found in the tree)")
    else:
        lines.append("score    %d/100   grade %s" % (value, grade))
        lines.append("         critical %d  high %d  medium %d  low %d" % (
            by_sev["critical"], by_sev["high"], by_sev["medium"], by_sev["low"]))
    lines.append("")

    if not findings:
        lines.append("FINDINGS")
        lines.append("  none")
        lines.append("")
    else:
        lines.append("FINDINGS")
        for f in findings:
            loc = f["path"] if f["line"] == 0 else "%s:%d" % (f["path"], f["line"])
            lines.append("  [%-8s] %s  %s" % (f["severity"], f["id"], f["title"]))
            lines.append("             at %s" % loc)
            if f["snippet"]:
                lines.append("             %s" % f["snippet"])
            lines.append("             owasp: %s" % f["owasp"])
            lines.append("             why: %s" % _wrap(f["why"], 70, 13))
            lines.append("             fix: %s" % _wrap(f["fix"], 70, 13))
            lines.append("")

    cov = _coverage(res)
    lines.append("COVERAGE LIMITS")
    for c in cov:
        lines.append("  - %s" % c)
    lines.append("")
    return "\n".join(lines)


def _wrap(text, width, indent):
    words, rows, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            rows.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        rows.append(cur)
    pad = "\n" + " " * indent
    return pad.join(rows)


def _coverage(res):
    out = []
    sk = res["skipped"]
    if not res["has_model_call"]:
        out.append("No model call was found. Either the target is not an LLM "
                   "application, or the call is behind a wrapper this scanner does "
                   "not recognise. Not assessed is not the same as clean.")
    out.append("Static analysis only: this reads text. It cannot see which "
               "instruction the model actually received at runtime, whether a "
               "guard was bypassed, or what a retrieved document contained.")
    out.append("Rules match patterns, not data flow. A guard three functions away "
               "from the interpolated string will still be reported — treat "
               "LAI-101 and LAI-102 hits as 'needs a human read', not as proof.")
    if sk.get("files"):
        out.append("Skipped %d files with extensions outside the audited set." % sk["files"])
    if sk.get("dirs"):
        out.append("Skipped %d dependency/build directories (node_modules, .git, "
                   "dist, venv and similar)." % sk["dirs"])
    if sk.get("too_many"):
        out.append("File cap reached: %d files were not scanned." % sk["too_many"])
    if sk.get("unreadable"):
        out.append("%d files could not be decoded and were not scanned." % sk["unreadable"])
    out.append("The live probe mode is separate and opt-in. It is the only part "
               "that sends traffic, and only to the endpoint you name.")
    return out


def render_markdown(res, target):
    findings = res["findings"]
    value, grade = score(findings, res["has_model_call"])
    by_sev = counts(findings)
    total = len(findings) or 1
    out = []
    out.append("# LLM application audit")
    out.append("")
    out.append("`%s`" % target)
    out.append("")
    if value is None:
        out.append("**Score: not assessed** — no model call found in the tree.")
    else:
        out.append("**Score: %d/100 (grade %s)**" % (value, grade))
        out.append("")
        out.append("| severity | count | |")
        out.append("| --- | --- | --- |")
        for sev in R.SEVERITY_ORDER:
            out.append("| %s | %d | `%s` |" % (sev, by_sev[sev],
                                               _bar(by_sev[sev], total)))
    out.append("")
    out.append("Scanned %d files, %.1f KB." % (res["files_scanned"],
                                               res["bytes_scanned"] / 1024.0))
    out.append("")

    if findings:
        out.append("## Findings")
        out.append("")
        for f in findings:
            loc = f["path"] if f["line"] == 0 else "%s:%d" % (f["path"], f["line"])
            out.append("### %s — %s" % (f["id"], f["title"]))
            out.append("")
            out.append("- **Severity:** %s" % f["severity"])
            out.append("- **OWASP:** %s" % f["owasp"])
            out.append("- **Where:** `%s`" % loc)
            if f["snippet"]:
                out.append("- **Evidence:** `%s`" % f["snippet"].replace("`", "'"))
            out.append("")
            out.append(f["why"])
            out.append("")
            out.append("**Fix.** %s" % f["fix"])
            out.append("")
    else:
        out.append("## Findings")
        out.append("")
        out.append("None of the audited patterns matched.")
        out.append("")

    out.append("## Coverage limits")
    out.append("")
    for c in _coverage(res):
        out.append("- %s" % c)
    out.append("")
    return "\n".join(out)


def render_json(res, target):
    value, grade = score(res["findings"], res["has_model_call"])
    return json.dumps({
        "target": target,
        "score": value,
        "grade": grade,
        "counts": counts(res["findings"]),
        "files_scanned": res["files_scanned"],
        "bytes_scanned": res["bytes_scanned"],
        "has_model_call": res["has_model_call"],
        "findings": res["findings"],
        "skipped": res["skipped"],
        "coverage_limits": _coverage(res),
    }, ensure_ascii=False, indent=2)
