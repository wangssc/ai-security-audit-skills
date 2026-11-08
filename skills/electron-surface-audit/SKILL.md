---
name: electron-surface-audit
description: Audit a local Electron application for the configuration and code patterns that turn a renderer compromise into arbitrary code execution — fuse state, ASAR integrity, nodeIntegration, contextIsolation, sandbox, IPC sender validation, openExternal guards, updater signing. Reads bytes off disk, never launches the target. Use when asked to review, harden, triage, or review-a-dependency desktop app built on Electron.
license: MIT
---

# Electron surface audit

A shipped Electron app has two security surfaces: the fuses compiled into the
executable, and the JavaScript that runs with whatever privilege those fuses allow.
This skill reads both from disk and reports what an attacker would use first.

No window opens. No code runs. No network request is made. Every finding cites a
file and a line, or explicitly says the evidence is "absence of a mitigation".

## When to use it

- "Is this app safe?" — you have a `.exe` / `.app` / install directory and need an answer with evidence.
- A desktop app you ship is about to go out and nobody has looked at `webPreferences`.
- Someone wants to know why a vendor's fix is or is not enough.
- A dependency or a downloaded tool needs a quick posture check before you run it.

## Run it

```bash
python scripts/audit.py "C:\Program Files\SomeApp\SomeApp.exe"
python scripts/audit.py ./SomeApp.app --json
python scripts/audit.py ./resources/app.asar --markdown report.md
```

The target can be the executable, the installed directory, or the `.asar` directly.
`--json` for machine consumption, `--markdown` to also write a report file.
`--fail-on critical|high|medium|low|none` controls the exit code (default: high).
`--include-deps` widens the scan into bundled `node_modules` (off by default).

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` target
unreadable.

## What it looks at

**Fuses** — nine compile-time switches in the executable. The tool finds the fuse
table by its sentinel, decodes the positional state array, and compares each value
against its safe state. A build with `RunAsNode` enabled and `OnlyLoadAppFromAsar`
disabled has handed the whole app to anyone who can run it with an environment
variable.

**ASAR integrity** — whether `EnableEmbeddedAsarIntegrityValidation` is on, and
whether the archive actually sits where the executable expects it. If the archive
is missing the tool says so; it does not fall back to "looks fine".

**Application code** — twenty rules over the app's own JavaScript and HTML, with
comments stripped and `node_modules` excluded. Each rule carries the reason it
matters and the change that resolves it. Rules that can be satisfied by nearby code
(a URL guard above `openExternal`) check for that guard and suppress the finding
rather than crying wolf.

## Reading the result

`score 0–100` with a letter grade, computed from fuse penalties plus rule penalties
on an exponential curve, and capped at 65 whenever a critical issue exists. A
critical issue is not diluted by a small codebase.

`not assessed` is a real outcome. If neither a fuse table nor an application archive
could be read, the tool refuses to print 100 — a launcher and a hardened app must
not look the same.

Every finding has four parts: where, why, fix, reference. The reference points at the
Electron security checklist item it comes from, so the recommendation is checkable
rather than asserted.

## What it cannot do

- It does not run the app, so it cannot see runtime state: which URL a window
  actually loaded, what the preload exposed at runtime, whether a CSP was applied by
  the server.
- It does not do data-flow analysis. `openExternal(x)` where `x` is validated three
  functions away will still be reported. Treat those as "needs a human look", not as
  proof of a bug.
- It reads the archive that is present. If a live `app.asar` was replaced and only a
  `.bak` remains, it audits the backup and says so.
- A pre-fuse build (Electron < 12) has no fuse table. That is a finding about the
  Electron version, not a clean bill of health.

## Turning findings into a fix

Order matters. Fix a critical before a high, and fix configuration before code:

1. **Fuses** — flip them at package time with `@electron/fuses`. These cost nothing
   at runtime and remove whole classes of attack.
2. **`webPreferences`** — `nodeIntegration: false`, `contextIsolation: true`,
   `sandbox: true`. If the app breaks, the preload is doing too much; narrow it.
3. **IPC** — validate `event.senderFrame.url` in every `ipcMain` handler and treat
   payload fields as untrusted.
4. **`openExternal`** — parse with `new URL()`, allow only `https:`, compare host
   against an allowlist.
5. **Updater** — signed manifests, pinned key, artifact verified before apply.

Re-run after each step. The score is a progress indicator, not a target: going from
21 to 60 by deleting rules would be a worse app, not a better one.

## Files

- `scripts/audit.py` — entry point, scoring, text and Markdown rendering
- `scripts/fuses.py` — fuse table locator and decoder
- `scripts/fuse_map.py` — the nine fuses: id, safe state, severity, why, fix
- `scripts/asar.py` — ASAR reader (header anchor, member extraction)
- `scripts/rules.py` — twenty source rules with guards and absence checks
- `references/checklist.md` — the underlying checklist, with what each item costs when ignored
