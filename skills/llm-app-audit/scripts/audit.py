#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Entry point for llm-app-audit.

Two modes, deliberately separate:

  static  (default)  reads bytes off disk. No network, no imports of the
                     target, no execution. Cannot cause an incident.
  probe   (opt-in)   sends unsolicited text to an endpoint you name. It will
                     look like an attack in that endpoint's logs, because it is
                     one. Only run it against something you are authorised to
                     test.

Exit codes:
  0  nothing at or above the threshold
  1  findings at or above the threshold
  2  target unreadable
  3  probe mode failed to run
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import report as report_mod    # noqa: E402
import rules as R              # noqa: E402
import scan as scan_mod        # noqa: E402

# probe.py is imported lazily inside _run_probe. Static mode must not even load
# the networking module: a skill that audits other people's code should be
# inspectable with its network path visibly unused.

VERSION = "1.0.0"


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="audit",
        description="Static security audit of an LLM application: prompt "
                    "construction, retrieval isolation, tool exposure, output "
                    "handling, and the operational controls around them. Reads "
                    "bytes only; never launches or imports the target.")
    ap.add_argument("target", help="project directory, single file, or prompt file")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--markdown", metavar="FILE", help="also write a Markdown report")
    ap.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "none"],
                    help="exit 1 if any finding at or above this severity (default: high)")
    ap.add_argument("--version", action="version", version="llm-app-audit " + VERSION)

    live = ap.add_argument_group("live probe mode (opt-in, sends traffic)")
    live.add_argument("--probe", action="store_true",
                      help="run the probe set against --endpoint instead of only scanning")
    live.add_argument("--endpoint", help="OpenAI-compatible chat completions URL")
    live.add_argument("--model", default=None, help="model identifier to send")
    live.add_argument("--api-key", default=None,
                      help="bearer token; defaults to $OPENAI_API_KEY")
    live.add_argument("--canary", default=None,
                      help="a string you planted in the target's system prompt. "
                           "Judging is impossible without it.")
    live.add_argument("--canary-alt", default=None,
                      help="a second planted marker (e.g. a forbidden phrase)")
    live.add_argument("--lang", default="en", choices=["en", "zh"],
                      help="probe language (default: en)")
    live.add_argument("--out", default="probe-results",
                      help="directory for probe evidence (default: probe-results)")
    live.add_argument("--dry-run", action="store_true",
                      help="print the probe payloads without sending anything")
    live.add_argument("--header", action="append", default=[],
                      metavar="K:V", help="extra HTTP header, repeatable")

    args = ap.parse_args(argv)

    if not os.path.exists(args.target):
        sys.stderr.write("error: target not found: %s\n" % args.target)
        return 2

    res = scan_mod.scan(args.target)

    if args.probe or args.dry_run:
        return _run_probe(args, res)

    if args.json:
        print(report_mod.render_json(res, args.target))
    else:
        print(report_mod.render_text(res, args.target))

    if args.markdown:
        md = report_mod.render_markdown(res, args.target)
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(md)
        if not args.json:
            print("markdown written to %s" % args.markdown)

    return _exit_code(res["findings"], args.fail_on)


def _run_probe(args, res):
    import probe as probe_mod  # imported here, not at module scope

    if not args.dry_run:
        if not args.endpoint:
            sys.stderr.write("error: --probe needs --endpoint\n")
            return 3
        if not args.model:
            sys.stderr.write("error: --probe needs --model\n")
            return 3
        if not args.canary:
            sys.stderr.write(
                "error: --probe needs --canary\n\n"
                "  Judging a system-prompt leak requires a string you know is inside\n"
                "  the prompt. Plant one first (an unusual token such as\n"
                "  CANARY-8F21XQ in the system prompt), then pass it here. Without it\n"
                "  the results cannot be graded and this tool will not pretend.\n")
            return 3

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    headers = {}
    for item in args.header:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()

    rows = probe_mod.run(
        endpoint=args.endpoint or "(dry run)",
        model=args.model or "(dry run)",
        api_key=api_key,
        canary=args.canary or "CANARY-PLACEHOLDER",
        canary_alt=args.canary_alt,
        lang=args.lang,
        outdir=args.out,
        dry_run=args.dry_run,
        extra_headers=headers or None,
    )

    text = probe_mod.render(rows, args.target, args.endpoint or "(dry run)")
    print(text)
    if not args.dry_run:
        path = os.path.join(args.out, "probe-report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("evidence written to %s and %s"
              % (path, os.path.join(args.out, "probe-raw.jsonl")))

    fails = [r for r in rows if r["verdict"] == "FAIL"]
    return 1 if (fails and args.fail_on != "none") else 0


def _exit_code(findings, threshold):
    if threshold == "none" or not findings:
        return 0
    limit = R.SEVERITY_ORDER.index(threshold)
    for f in findings:
        if R.SEVERITY_ORDER.index(f["severity"]) <= limit:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
