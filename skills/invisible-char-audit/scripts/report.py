# -*- coding: utf-8 -*-
"""Scoring and rendering.

The score is capped at 55 while any critical finding stands, for the same reason
a bidi override cannot be averaged away: one invisible `RLO` in a source file is
not "mostly clean", it is a file whose displayed form cannot be trusted.
"""

import json
import math

WEIGHT = {"critical": 30, "high": 14, "medium": 6, "low": 2}
ORDER = ["critical", "high", "medium", "low"]
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]

# Per-severity contribution caps.
#
# Without them, sixty correct-but-trivial low findings (full-width spaces in a
# Chinese template) scored 13/100 — worse than a file containing one live bidi
# override. Volume of small things must not outweigh one dangerous thing.
# Critical is uncapped on purpose: a thousand bidi controls is not a rounding
# error, it is a file that cannot be trusted at all.
CAP = {"critical": 10_000, "high": 60, "medium": 30, "low": 10}


def _penalty(findings):
    per = {s: 0 for s in ORDER}
    for f in findings:
        per[f["severity"]] += WEIGHT[f["severity"]]
    return sum(min(per[s], CAP[s]) for s in ORDER)


def score(findings, files_scanned):
    if not files_scanned:
        return None, "not assessed"
    penalty = _penalty(findings)
    raw = round(100 * math.exp(-penalty / 60.0))
    if any(f["severity"] == "critical" for f in findings):
        raw = min(raw, 55)
    raw = max(0, min(100, raw))
    for floor, letter in GRADES:
        if raw >= floor:
            return raw, letter
    return raw, "F"


def counts(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in ORDER}


def render_text(res, target):
    findings = res["findings"]
    value, grade = score(findings, res["files_scanned"])
    c = counts(findings)
    out = []
    out.append("target   %s" % target)
    out.append("scanned  %d files, %.1f KB" % (res["files_scanned"],
                                               res["bytes_scanned"] / 1024.0))
    out.append("")
    if value is None:
        out.append("score    not assessed (nothing readable was found)")
    else:
        out.append("score    %d/100   grade %s" % (value, grade))
        out.append("         critical %d  high %d  medium %d  low %d"
                   % (c["critical"], c["high"], c["medium"], c["low"]))
    out.append("")
    out.append("FINDINGS" if findings else "FINDINGS\n  none")
    for f in findings:
        out.append("  [%-8s] %s  %s" % (f["severity"], f["id"], f["title"]))
        out.append("             at %s:%d:%d   %s  %s"
                   % (f["path"], f["line"], f["col"], f["codepoint"], f["name"]))
        if f.get("char"):
            out.append("             char %s" % f["char"])
        out.append("             %s" % _wrap(f["detail"], 68, 13))
        out.append("             fix: %s" % _wrap(f["fix"], 64, 18))
        out.append("")
    out.append("COVERAGE LIMITS")
    out.append("  - Only characters with a known dangerous role are reported. A "
               "codepoint absent from the tables is not evidence of safety.")
    out.append("  - Homoglyph matching is a curated subset of the Unicode "
               "confusables list: the letters that actually appear in impostors.")
    out.append("  - The scanner reads bytes and never executes, imports, or "
               "renders the target.")
    return "\n".join(out)


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
    return ("\n" + " " * indent).join(rows)


def render_markdown(res, target):
    findings = res["findings"]
    value, grade = score(findings, res["files_scanned"])
    out = ["# Invisible character audit", "", "`%s`" % target, ""]
    if value is None:
        out.append("**Score: not assessed**")
    else:
        out.append("**Score: %d/100 (grade %s)**" % (value, grade))
    out.append("")
    out.append("Scanned %d files, %.1f KB." % (res["files_scanned"],
                                               res["bytes_scanned"] / 1024.0))
    out.append("")
    if not findings:
        out.append("No listed character was found.")
        return "\n".join(out)
    out.append("| severity | id | where | codepoint |")
    out.append("| --- | --- | --- | --- |")
    for f in findings:
        out.append("| %s | %s | `%s:%d:%d` | %s |"
                   % (f["severity"], f["id"], f["path"], f["line"], f["col"],
                      f["codepoint"]))
    out.append("")
    for f in findings:
        out.append("### %s — %s" % (f["id"], f["title"]))
        out.append("")
        out.append("- **Severity:** %s" % f["severity"])
        out.append("- **Where:** `%s:%d:%d`" % (f["path"], f["line"], f["col"]))
        out.append("- **Codepoint:** `%s` (%s)" % (f["codepoint"], f["name"]))
        out.append("")
        out.append(f["detail"])
        out.append("")
        out.append("**Fix.** %s" % f["fix"])
        out.append("")
    return "\n".join(out)


def render_json(res, target):
    value, grade = score(res["findings"], res["files_scanned"])
    return json.dumps({
        "target": target, "score": value, "grade": grade,
        "counts": counts(res["findings"]),
        "files_scanned": res["files_scanned"],
        "bytes_scanned": res["bytes_scanned"],
        "findings": res["findings"],
        "skipped": res["skipped"],
    }, ensure_ascii=False, indent=2)
