# Electron Surface Audit

**Your app ships Chromium, a Node runtime, and a JavaScript bundle that runs with
your users' permissions. This audits all three from disk — in about two seconds, on
a machine that never opens a window.**

```bash
python scripts/audit.py "C:\Program Files\SomeApp\SomeApp.exe"
```

```
target   C:\Program Files\SomeApp\SomeApp.exe
asar     C:\Program Files\SomeApp\resources\app.asar

score    21/100   grade F (critical)
         fuse penalty 117, code penalty 23

FUSES
  [RISK] Run as Node                        enabled   safe=disabled
  [RISK] Embedded ASAR integrity            disabled  safe=enabled
  [RISK] Only load app from ASAR            disabled  safe=enabled
  [RISK] file:// extra privileges           enabled   safe=disabled
  [ ok ] WASM trap handlers                 enabled   safe=enabled
  ...

FINDINGS
  [critical] ES-001  nodeIntegration is enabled
             at Downloader.js:20
             webPreferences: {nodeIntegration: true}
             fix: Set nodeIntegration: false and move the privileged calls into a
                  preload script that exposes a narrow, argument-validated API.

  [high    ] ES-011  shell.openExternal called with a non-literal argument
             at WindowController.js:158
             shell.openExternal(url);
             fix: Parse with new URL(), allow only http(s), compare the host
                  against an allowlist.
```

Those two reports are real and shipped in `references/examples/`: a 2019-era note
app at 27/100, a current AI desktop client at 21/100. Both have live critical
findings. Neither vendor advertises them.

---

## The problem

Electron gives you a browser and a Node process in one binary. That combination is
productive and it is also a loaded gun: the boundary between "renders your UI" and
"runs code as the user" is a handful of booleans in `webPreferences`, and every one
of them defaults to the friendly value rather than the safe one.

The failure is not exotic. It is this:

1. The app sets `nodeIntegration: true` because a feature needed `fs` in 2019.
2. The renderer loads a page — possibly remote, possibly with a third-party widget.
3. Anything that achieves script execution in that page can now `require('child_process')`.

No memory corruption, no sandbox escape, no exploit chain. One config flag, one XSS,
full user compromise.

And it is invisible from the outside. The app looks normal, the installer is signed,
the icon is polished. The only way to know is to read the binary and the archive.

## What this does

Nine checks on the executable. Twenty rules on the archive.

**Fuses** — the compile-time switchboard Electron embeds in the binary. The tool
finds the table by its sentinel, decodes the positional state array, and compares
each of the nine fuses against its safe value. `RunAsNode: enabled` means
`ELECTRON_RUN_AS_NODE=1 app.exe` turns your signed application into a Node
interpreter with your bundle's identity. `OnlyLoadAppFromAsar: disabled` means a
loose `app/` directory next to the archive wins at launch.

**ASAR integrity** — whether the archive the executable will load is the one you
signed, and whether the tool is even looking at the right file. If a live `app.asar`
is missing and only `app.asar.bak` remains, the report says which one it audited.

**Application code** — twenty rules across the app's own JavaScript and HTML:

| id | severity | what it catches |
| --- | --- | --- |
| ES-001 | critical | `nodeIntegration: true` |
| ES-002 | critical | `contextIsolation: false` |
| ES-003 | high | `sandbox: false` |
| ES-004 | critical | `webSecurity: false` |
| ES-005 | high | `allowRunningInsecureContent: true` |
| ES-006 | medium | `experimentalFeatures: true` |
| ES-007 | medium | `enableBlinkFeatures` |
| ES-008 | high | remote content over plain HTTP |
| ES-009 | high | remote content in a privileged window |
| ES-010 | medium | no Content-Security-Policy |
| ES-011 | high | `shell.openExternal` with an unguarded argument |
| ES-012 | high | `ipcMain` handler with no sender validation |
| ES-013 | medium | `<webview>` enabled |
| ES-014 | medium | window-open handler returns `allow` |
| ES-015 | medium | no `will-navigate` guard |
| ES-016 | high | preload exposes a raw module |
| ES-017 | medium | no permission request handler |
| ES-018 | high | updater trusts an unsigned feed |
| ES-019 | medium | `remote` module |
| ES-020 | low | DevTools opened unconditionally |

Comments are stripped before matching, so documentation and commented-out examples do
not raise findings. `node_modules` is excluded by default: the audit is about the code
you maintain, and telling a publisher to patch a dependency's defaults is not
actionable.

**Guards suppress noise.** `ES-011` checks the statement and the four lines above it
for a `new URL()`, a `protocol === 'https:'` comparison, or an allowlist. If the guard
is there, the finding is suppressed — and the suppression is recorded in the JSON, so
a reader can audit the auditor.

## Why this beats prompting it yourself

You can ask a model "is this Electron app secure?" It will answer confidently. It
cannot tell you:

- **The fuse state of a compiled binary.** There is no API for it. The bytes are at a
  sentinel-delimited table inside the `.exe`, and reading them means locating that
  sentinel, decoding a positional state array, and knowing what each of the nine
  values means for exploitability. A model reading your source code never sees this at
  all.
- **Which archive the executable will actually load.** `resources/app.asar`,
  `resources/app/*.asar`, or a `.bak` that outlived the live file — the resolution
  order matters and a wrong guess audits the wrong program.
- **Whether an absence is evidence.** "No `setPermissionRequestHandler` anywhere" means
  one thing when you read 14 files and another when you read 120 of 9,904. The tool
  tracks whether the scan was complete and refuses to assert absence from a partial
  read.
- **A number that discriminates.** A three-finding legacy app and a twenty-finding
  modern app both score zero under linear penalties. Exponential decay plus a critical
  cap keeps the score meaningful across very different codebases.

The output is also reproducible. You can paste a report into a code review, diff two
versions of an app, and put `--fail-on high` in CI. A chat transcript does none of
that.

## Install

No dependencies. Python 3.8+, standard library only.

```bash
git clone https://github.com/<you>/electron-surface-audit
cd electron-surface-audit
python scripts/audit.py --help
```

As an Agent Skill, drop the directory into your agent's skills folder
(`~/.claude/skills/`, `~/.codex/skills/`, or whatever your client scans). The
`SKILL.md` frontmatter tells the agent when to reach for it.

## Usage

```bash
# an installed app
python scripts/audit.py "C:\Program Files\Some App\Some App.exe"

# a macOS bundle (finds Contents/Resources/app.asar)
python scripts/audit.py /Applications/Some\ App.app

# the archive on its own — no fuse data, code only
python scripts/audit.py ./resources/app.asar

# machine-readable, plus a report file
python scripts/audit.py ./app.asar --json --markdown audit.md

# CI gate
python scripts/audit.py ./app.asar --fail-on high   # exit 1 on any high or critical
```

| flag | default | meaning |
| --- | --- | --- |
| `--json` | off | emit JSON instead of text |
| `--markdown FILE` | off | also write a Markdown report |
| `--max-files N` | 400 | cap on script files read |
| `--max-bytes N` | 32 MiB | cap on total source bytes |
| `--include-deps` | off | also scan bundled `node_modules` |
| `--fail-on LEVEL` | `high` | exit 1 at this severity or worse; `none` disables |

Exit codes: `0` clean at threshold, `1` findings, `2` target unreadable or missing.

## Scoring

```
penalty = Σ fuse weights + Σ rule weights
score   = round(100 · e^(−penalty/90))
score   = min(score, 65)   if any critical exists
```

Fuse weights: critical 25, high 12, medium 5, low 1.
Rule weights: critical 20, high 10, medium 5, low 1.

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.

`not assessed` is a distinct outcome. When neither a fuse table nor an application
archive can be read, the tool prints `not assessed` rather than 100. A launcher stub
and a hardened app must not look the same — that single design decision is why this
tool is usable in a review.

## Coverage limits (read these)

- **Static only.** The tool never launches the target. Runtime decisions — which URL
  a window actually loaded, what the preload actually exposed, whether the server sent
  a CSP — are outside what source and bytes can tell you.
- **No data-flow analysis.** `openExternal(x)` where `x` was validated three functions
  away is still reported. Treat those as "needs a human look".
- **Absence checks depend on scope.** `ES-010`, `ES-015`, `ES-017` fire when something
  is not found. If `--max-files` truncated the scan, each such finding is marked
  `partial_evidence: true` and should be re-checked with a wider budget.
- **Pre-fuse builds.** Electron < 12 has no fuse table. That is a finding about the
  Electron version, not a pass.
- **One app per run.** Nothing here audits a runtime, a server, or a plugin host
  separately.

## What a fix looks like

Order matters: configuration before code, critical before high.

1. **Flip the fuses** at package time with `@electron/fuses`. No runtime cost, and it
   removes entire attack classes.
2. **`webPreferences`** — `nodeIntegration: false`, `contextIsolation: true`,
   `sandbox: true`. If the app breaks, the preload was doing too much.
3. **IPC** — validate `event.senderFrame.url` in every handler; treat payload as
   untrusted.
4. **`openExternal`** — `new URL()`, `https:` only, host allowlist.
5. **Updater** — signed manifests, pinned key, verify the artifact before applying.

Re-run after each step. The score is a progress indicator, not a target: going from
21 to 60 by deleting rules would be a worse app.

## Repository layout

```
scripts/
  audit.py       entry point, scoring, text + Markdown rendering
  fuses.py       fuse table locator and decoder
  fuse_map.py    the nine fuses: id, safe state, severity, why, fix
  asar.py        ASAR reader (header anchor, member extraction)
  rules.py       twenty source rules with guards and absence checks
references/
  checklist.md   the reasoning behind every rule: what breaks, and why
  examples/      two real reports from shipped applications
SKILL.md         agent-facing entry point
```

## Known limitations, stated plainly

- The fuse decoder assumes the sentinel is intact. A vendor that strips it produces
  `no fuse table` rather than a guess.
- ASAR header offsets survive repacking because the JSON is located by its opening
  token and the pickle prefix is measured, but an archive with a rewritten *member*
  table would still parse and read wrong bytes. The tool reports the header position it
  used so the number is checkable.
- Rule `ES-012` cannot follow the payload into a helper. It reports the pattern; the
  fix states what the guard must check.
- Severity is about exploitability in a shipped app. A finding marked `medium` in a
  server-rendered marketing site is not the same risk as the same finding in a banking
  client — the report gives you the evidence to make that call, not the call itself.

## License

MIT. See `LICENSE`.

The checklist this tool implements is Electron's, which is public and maintained at
`electronjs.org/docs/latest/tutorial/security`. Rules are numbered and referenced so
each recommendation is checkable against the source rather than asserted.
