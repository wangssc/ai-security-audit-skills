"""Audit one local Electron application and print a findings report.

Usage:
    python audit.py <path-to-exe | path-to-app-dir | path-to-asar>
    python audit.py <target> --json
    python audit.py <target> --markdown report.md
    python audit.py <target> --max-files 400

Exit codes: 0 clean, 1 findings at or above --fail-on (default high), 2 target not
readable, 3 unsupported target.

Everything happens against bytes on disk. Nothing is executed, no window is opened,
no network request is made.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import asar as A  # noqa: E402
import fuses as F  # noqa: E402
import rules as R  # noqa: E402

WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 1}
RULE_WEIGHT = {"critical": 20, "high": 10, "medium": 5, "low": 1}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def locate(target: str) -> dict[str, Any]:
    """Work out what kind of thing the caller handed us."""
    target = os.path.abspath(target)
    if not os.path.exists(target):
        return {"kind": "missing", "path": target}

    if os.path.isdir(target):
        # An installed app directory: look for the asar and for any executable.
        found_asar = None
        for root, _dirs, names in os.walk(target):
            if "app.asar" in names:
                found_asar = os.path.join(root, "app.asar")
                break
        exe = None
        for root, _dirs, names in os.walk(target):
            for n in names:
                if n.lower().endswith(".exe"):
                    exe = os.path.join(root, n)
                    break
            if exe:
                break
        return {"kind": "dir", "path": target, "exe": exe, "asar": found_asar}

    low = target.lower()
    if low.endswith(".asar"):
        return {"kind": "asar", "path": target, "asar": target, "exe": None}
    if low.endswith(".exe") or os.access(target, os.X_OK):
        return {"kind": "exe", "path": target, "exe": target, "asar": A.find_asar(target)}
    return {"kind": "other", "path": target, "exe": None, "asar": A.find_asar(target)}


def collect_sources(
    asar_path: str,
    max_files: int,
    max_bytes: int,
    include_deps: bool = False,
) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    """Read every JS/HTML member, bounded by count and total size.

    `node_modules` is skipped by default: the audit is about the code the app ships
    and maintains, and a bundled dependency's defaults are not something the
    publisher can be told to change. Pass include_deps to widen it.
    """
    parsed = A.parse_asar(asar_path)
    if not parsed["ok"]:
        return [], {"ok": False, "reason": parsed["reason"]}

    wanted = []
    skipped_deps = 0
    for f in parsed["files"]:
        p = f["path"]
        if not p.endswith((".js", ".mjs", ".cjs", ".html", ".htm")):
            continue
        if not include_deps:
            norm = p.replace("\\", "/")
            # Both layouts occur: a top-level `node_modules/...` and a nested
            # `app/node_modules/...`. Testing for a leading prefix as well as a
            # slash-wrapped segment is what catches the first one.
            if norm.startswith("node_modules/") or "/node_modules/" in norm:
                skipped_deps += 1
                continue
        wanted.append(f)

    # Prefer files that plausibly hold the main process, preload, or renderer HTML.
    def rank(f: dict) -> tuple[int, int]:
        low = f["path"].lower()
        score = 3
        if "preload" in low:
            score = 0
        elif low.endswith((".html", ".htm")):
            score = 1
        elif "main" in low or "index" in low or "app" in low or "electron" in low:
            score = 2
        return (score, -(f.get("size") or 0))

    wanted.sort(key=rank)

    sources: list[tuple[str, str]] = []
    total = 0
    for f in wanted:
        if len(sources) >= max_files:
            break
        size = f.get("size") or 0
        if total + size > max_bytes:
            continue
        raw = A.read_file(parsed, f["path"], limit=min(size or (2 << 20), 2 << 20))
        if not raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", "replace")
        sources.append((f["path"], text))
        total += len(text)

    meta = {
        "ok": True,
        "asar_files": parsed["file_count"],
        "candidates": len(wanted),
        "scanned": len(sources),
        "scanned_bytes": total,
        "skipped_deps": skipped_deps,
        "include_deps": include_deps,
        "truncated": len(sources) < len(wanted),
    }
    return sources, meta


def score(fuse_rows: list[dict], findings: list[dict]) -> dict[str, Any]:
    """One number a reader can act on, plus the components that produced it.

    Penalty accumulates linearly but the score decays exponentially, so the first
    critical issue costs far more than the tenth. Without that curve a pre-fuse
    app with three findings and a shipped app with twenty both land on zero and the
    number stops discriminating. A critical issue also caps the ceiling: no app
    that hands a renderer Node access is "mostly hardened" no matter how few lines
    of code it has.
    """
    import math

    fuse_penalty = sum(WEIGHT.get(r["severity"], 0) for r in fuse_rows if r["risky"])
    rule_penalty = sum(RULE_WEIGHT.get(f["severity"], 0) for f in findings)
    penalty = fuse_penalty + rule_penalty

    total = round(100 * math.exp(-penalty / 90)) if penalty else 100

    has_critical = any(r["risky"] and r["severity"] == "critical" for r in fuse_rows) or any(
        f["severity"] == "critical" for f in findings
    )
    if has_critical:
        total = min(total, 65)

    if total >= 90:
        grade, label = "A", "hardened"
    elif total >= 75:
        grade, label = "B", "mostly hardened"
    elif total >= 60:
        grade, label = "C", "exposed"
    elif total >= 40:
        grade, label = "D", "weak"
    else:
        grade, label = "F", "critical"
    return {
        "score": total,
        "penalty": penalty,
        "grade": grade,
        "label": label,
        "fuse_penalty": fuse_penalty,
        "rule_penalty": rule_penalty,
        "capped_by_critical": has_critical,
    }


def audit(
    target: str,
    max_files: int = 400,
    max_bytes: int = 32 << 20,
    include_deps: bool = False,
) -> dict[str, Any]:
    loc = locate(target)
    if loc["kind"] == "missing":
        return {"ok": False, "reason": f"path does not exist: {loc['path']}"}

    result: dict[str, Any] = {
        "ok": True,
        "target": loc,
        "fuses": {"found": False},
        "asar": {"ok": False},
        "findings": [],
        "limits": [],
    }

    # 1. Fuses
    exe = loc.get("exe")
    if exe and os.path.isfile(exe):
        scan = F.scan_fuses(exe)
        if scan["found"]:
            rows = F.describe(scan)
            primary = scan.get("tables") or []
            result["fuses"] = {
                "found": True,
                "exe": exe,
                "offset": primary[0]["offset"] if primary else None,
                "rows": rows,
            }
        else:
            result["fuses"] = {"found": False, "exe": exe, "reason": scan.get("reason")}
            result["limits"].append(
                "No fuse table: this is a pre-fuse Electron build (< 12) or a non-Electron executable. "
                "Fuse-level hardening cannot be assessed; treat every fuse as unset."
            )
    else:
        result["limits"].append("No executable was supplied, so fuse state was not read.")

    # 2. ASAR + source scan
    asar_path = loc.get("asar")
    if asar_path and os.path.isfile(asar_path):
        sources, meta = collect_sources(asar_path, max_files, max_bytes, include_deps)
        result["asar"] = {"path": asar_path, **meta}
        if meta.get("ok"):
            raw_findings = []
            for p, text in sources:
                raw_findings.extend(R.scan_source(p, text))
            raw_findings.extend(R.scan_presence(sources, complete=not meta.get("truncated")))

            suppressed = [f for f in raw_findings if f.get("suppressed")]
            findings = [f for f in raw_findings if not f.get("suppressed")]
            findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["rule"], f["file"], f["line"]))
            result["findings"] = findings
            result["suppressed"] = [
                {"rule": s["rule"], "file": s["file"], "line": s["line"], "reason": s["suppressed_by"]}
                for s in suppressed
            ]
            if meta.get("truncated"):
                result["limits"].append(
                    f"Scanned {meta['scanned']} of {meta['candidates']} candidate script files "
                    f"(caps: {max_files} files / {max_bytes // (1 << 20)} MB). Raise --max-files or "
                    f"pass --include-deps to cover more."
                )
    else:
        result["limits"].append(
            "No application archive was found next to the executable, so application code was not scanned."
        )

    # 3. Coverage: what did we actually look at?
    # A missing archive and a missing fuse table mean nothing was assessed. Reporting
    # that as 100/100 would call a launcher "hardened" and quietly pass an app whose
    # layout we simply failed to parse.
    fuse_rows = result["fuses"].get("rows", []) if result["fuses"].get("found") else []
    looked_at_fuses = bool(result["fuses"].get("found"))
    looked_at_code = bool(result["asar"].get("ok") and result["asar"].get("scanned"))
    result["coverage"] = {
        "fuses": looked_at_fuses,
        "code": looked_at_code,
        "assessed": looked_at_fuses or looked_at_code,
    }

    if not (looked_at_fuses or looked_at_code):
        result["score"] = {
            "score": None,
            "penalty": 0,
            "grade": "?",
            "label": "not assessed",
            "fuse_penalty": 0,
            "rule_penalty": 0,
            "capped_by_critical": False,
        }
        result["limits"].append(
            "Nothing could be assessed: no fuse table and no application archive. This is not a "
            "clean result — point the tool at the real Electron executable, or pass the .asar directly."
        )
    else:
        result["score"] = score(fuse_rows, result["findings"])

    result["summary"] = {
        "fuse_risks": sum(1 for r in fuse_rows if r["risky"]),
        "findings": len(result["findings"]),
        "by_severity": dict(Counter(f["severity"] for f in result["findings"])),
    }
    return result


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_text(res: dict[str, Any]) -> str:
    if not res["ok"]:
        return f"FAILED: {res['reason']}"

    out: list[str] = []
    t = res["target"]
    out.append(f"target   {t['path']}")
    if t.get("exe"):
        out.append(f"exe      {t['exe']}")
    if t.get("asar"):
        out.append(f"asar     {t['asar']}")

    s = res["score"]
    out.append("")
    if s["score"] is None:
        out.append("score    not assessed (nothing readable was found)")
    else:
        out.append(f"score    {s['score']}/100   grade {s['grade']} ({s['label']})")
        out.append(f"         fuse penalty {s['fuse_penalty']}, code penalty {s['rule_penalty']}")

    # Fuses
    out.append("")
    out.append("FUSES")
    if res["fuses"].get("found"):
        for r in res["fuses"]["rows"]:
            mark = "RISK" if r["risky"] else " ok "
            out.append(f"  [{mark}] {r['label']:<42} {r['state']:<9} safe={r['safe_state']}")
    else:
        out.append(f"  {res['fuses'].get('reason', 'not found')}")

    # Findings
    out.append("")
    out.append("FINDINGS")
    if not res["findings"]:
        out.append("  none")
    else:
        for f in res["findings"]:
            where = f"{f['file']}:{f['line']}" if f["file"] else "(absence check)"
            out.append(f"  [{f['severity']:<8}] {f['rule']}  {f['title']}")
            out.append(f"             at {where}")
            if f["excerpt"]:
                out.append(f"             {f['excerpt']}")
            out.append(f"             fix: {f['fix']}")

    if res["limits"]:
        out.append("")
        out.append("COVERAGE LIMITS")
        for lim in res["limits"]:
            out.append(f"  - {lim}")

    return "\n".join(out)


def render_markdown(res: dict[str, Any]) -> str:
    if not res["ok"]:
        return f"# Audit failed\n\n{res['reason']}\n"

    s = res["score"]
    if s["score"] is None:
        headline = "**Not assessed — nothing readable was found**"
        penalties = ""
    else:
        headline = f"**Score {s['score']}/100 — grade {s['grade']} ({s['label']})**"
        penalties = f"Penalties: fuses {s['fuse_penalty']}, code {s['rule_penalty']}"

    lines = [
        "# Electron surface audit",
        "",
        headline,
        "",
        f"- target: `{res['target']['path']}`",
    ]
    if res["target"].get("exe"):
        lines.append(f"- executable: `{res['target']['exe']}`")
    if res["target"].get("asar"):
        lines.append(f"- asar: `{res['target']['asar']}`")
    if penalties:
        lines += ["", penalties]
    lines.append("")

    lines.append("## Fuse state")
    lines.append("")
    if res["fuses"].get("found"):
        lines.append("| fuse | state | safe | verdict |")
        lines.append("| --- | --- | --- | --- |")
        for r in res["fuses"]["rows"]:
            verdict = "RISK" if r["risky"] else "ok"
            lines.append(f"| {r['label']} | {r['state']} | {r['safe_state']} | {verdict} |")
    else:
        lines.append(res["fuses"].get("reason", "not found"))
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not res["findings"]:
        lines.append("No rule matched.")
    else:
        for f in res["findings"]:
            where = f"`{f['file']}:{f['line']}`" if f["file"] else "absence check"
            lines.append(f"### {f['rule']} — {f['title']}")
            lines.append("")
            lines.append(f"- severity: **{f['severity']}**")
            lines.append(f"- where: {where}")
            if f["excerpt"]:
                lines.append(f"- code: `{f['excerpt']}`")
            lines.append(f"- why: {f['why']}")
            lines.append(f"- fix: {f['fix']}")
            lines.append(f"- reference: {f['ref']}")
            lines.append("")

    if res["limits"]:
        lines.append("## Coverage limits")
        lines.append("")
        for lim in res["limits"]:
            lines.append(f"- {lim}")
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="audit",
        description="Statically audit an Electron application: fuse configuration, ASAR layout, "
                    "and privileged API usage. Reads bytes only; never launches the target.",
    )
    ap.add_argument("target", help="path to the .exe, the installed app directory, or an .asar")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--markdown", metavar="FILE", help="also write a Markdown report")
    ap.add_argument("--max-files", type=int, default=400, help="cap on script files to scan (default 400)")
    ap.add_argument("--max-bytes", type=int, default=32 << 20, help="cap on total source bytes read")
    ap.add_argument("--include-deps", action="store_true",
                    help="also scan bundled node_modules (skipped by default: dependencies are not yours to patch)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high",
                    help="exit 1 when a finding at this severity or worse exists (default high)")
    args = ap.parse_args(argv)

    res = audit(args.target, max_files=args.max_files, max_bytes=args.max_bytes,
                include_deps=args.include_deps)

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(render_text(res))

    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(res))
        if not args.json:
            print(f"\nMarkdown report written to {args.markdown}")

    if not res["ok"]:
        return 2

    if args.fail_on != "none":
        threshold = SEV_RANK[args.fail_on]
        # Fuse risks are findings too. Leaving them out would let an app with a
        # critical fuse misconfiguration pass a `--fail-on critical` gate.
        severities = [f["severity"] for f in res["findings"]]
        if res["fuses"].get("found"):
            severities += [r["severity"] for r in res["fuses"]["rows"] if r["risky"]]
        worst = min((SEV_RANK[s] for s in severities), default=99)
        if worst <= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
