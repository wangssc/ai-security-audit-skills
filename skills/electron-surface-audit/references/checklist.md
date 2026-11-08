# The checklist, and what each item costs when ignored

This is the reasoning behind the rules. Electron's security checklist says *what* to
do; this file says *what happens* when you don't, and how the audit decides.

Two things determine the blast radius of any Electron bug:

1. **Can a remote page reach Node?** If yes, every XSS is remote code execution.
2. **Is the running code the code you signed?** If no, the supply chain is the app.

Almost every item below is one of those two, viewed from a different angle.

---

## 1. Only load secure content

**What breaks.** A cleartext URL is not authenticated. Whoever sits between the app
and the server decides what the window renders, and if that window has any privilege
the attacker inherits it.

**Detected by** `ES-008` (`loadURL('http://...')`), `ES-009` (any remote `loadURL`).

**Why `https` alone is not enough.** Loading a remote origin means the app's security
now depends on a server you do not ship. A correct answer for a store listing and a
correct answer for a bank client look the same in code but not in risk. `ES-009`
fires on both, at high, because the auditor should see it and decide.

---

## 2. Do not enable Node.js integration for remote content

**What breaks.** `nodeIntegration: true` gives page script `require`. From there:
`require('child_process').exec('calc')`. One XSS in a bundled UI library, one
compromised ad iframe, one injected script through a proxy — all become code
execution as the user.

**Detected by** `ES-001`, critical.

**The usual objection.** "But my renderer needs `fs`." It doesn't. It needs two file
operations, and those belong in the main process behind a channel that validates its
arguments. The migration is a day of work and removes the category.

---

## 3. Enable Context Isolation

**What breaks.** Without isolation the preload script and the page share one
JavaScript context. Anything the preload puts on `window` is visible to and
rewritable by page code. `contextBridge` is not protection when the bridge and the
page live in the same room.

**Detected by** `ES-002`, critical. Default since Electron 12, so this is almost
always an explicit `false` somebody left behind.

---

## 4. Enable process sandboxing

**What breaks.** A sandboxed renderer runs in a restricted process. Disabling it
means a renderer compromise reaches the filesystem the renderer user can read, not
just whatever the IPC layer exposes.

**Detected by** `ES-003`, high.

**The cost.** Preload scripts lose `require` under the sandbox. That is the point: it
forces the privileged surface into explicit channels instead of ambient module access.

---

## 5. Do not expose Electron APIs to untrusted web content

**What breaks.** `contextBridge.exposeInMainWorld('api', require('electron'))` is
`nodeIntegration` with extra steps. So is passing `ipcRenderer` itself — the page can
then call any channel the app registered.

**Detected by** `ES-016`, high. `ES-019` covers the removed `remote` module.

**The shape of a correct preload.** Named functions, fixed signatures, arguments
validated in the main process:

```js
contextBridge.exposeInMainWorld('app', {
  saveNote: (text) => ipcRenderer.invoke('note:save', String(text).slice(0, 4096)),
});
```

---

## 6. Do not disable `webSecurity`

**What breaks.** Same-origin policy off means any page in that window can read any
other origin's responses — including authenticated ones. This is a same-origin
bypass with a config flag, and it is the single fastest way to turn a rendering
issue into data theft.

**Detected by** `ES-004`, critical.

---

## 7. Define a Content Security Policy

**What breaks.** CSP is the second line: when markup injection happens anyway, CSP
decides whether the injected `<script>` runs. Without one, it does.

**Detected by** `ES-010`, medium — an absence check across the scanned HTML.

**Minimum useful policy.** `default-src 'self'; script-src 'self'; object-src 'none';
base-uri 'none'`. If the app needs `unsafe-inline`, the inline content is the bug.

---

## 8. Do not allow running insecure content

**What breaks.** An HTTPS page may load scripts over HTTP. The lock icon stays green
while the attacker controls the script.

**Detected by** `ES-005`, high.

---

## 9–10. Do not enable experimental features or Blink features

**What breaks.** Unshipped Chromium code is not covered by the usual review. Blink
feature flags have historically included switches that widen renderer capability.

**Detected by** `ES-006` (medium), `ES-007` (medium).

---

## 11. Verify WebView options

**What breaks.** A `<webview>` is a frame with its own preferences. A remote guest can
be given more privilege than the host if its attributes are not pinned — the host page
decides, and the host page may be showing attacker content.

**Detected by** `ES-013`, medium.

---

## 12. Handle session permission requests

**What breaks.** Camera, microphone, geolocation and notifications follow the default
policy. An app that never intended to use the microphone can be made to ask for it,
and the user has no reason to say no — it's the app they installed.

**Detected by** `ES-017`, medium — absence check for `setPermissionRequestHandler`.

---

## 13–14. Limit navigation and window creation

**What breaks.** Without a `will-navigate` guard, a link or a server-side redirect
moves the window to an origin the app never trusted. Without a window-open handler,
`window.open` lets page content choose where a new, possibly privileged, window goes.

**Detected by** `ES-015` (absence of `will-navigate`, medium), `ES-014`
(`setWindowOpenHandler` returning `allow`, medium).

---

## 15. Do not call `shell.openExternal` with untrusted content

**What breaks.** `openExternal` hands the string to the OS. `file://` opens local
paths; registered custom schemes can launch local programs with arguments; some
handlers leak local file existence through timing. With a URL from page content this
is a local-attack primitive.

**Detected by** `ES-011`, high — with a guard check: if a `new URL()`, a `protocol
=== 'https:'` comparison, or an allowlist appears in the statement or the four lines
above, the finding is suppressed. The suppression is recorded, not silently dropped,
so a reader can see what was excused and why.

---

## 16. Keep Electron current, and keep updates signed

**What breaks.** An updater that fetches from a URL without verifying a signature
means whoever controls that URL controls the code that runs at next launch. This is
not a renderer bug; it is a supply-chain bug, and it outranks everything else.

**Detected by** `ES-018`, high — `setFeedURL` calls, `autoUpdater.feedURL`
assignments, and `provider: "generic"` configurations.

---

## 17. Validate the sender of every IPC message

**What breaks.** Any frame in any window of the app can send any registered channel,
including a frame that ended up showing attacker-controlled content. A handler that
acts on the message does privileged work on request.

**Detected by** `ES-012`, high — `ipcMain.on` / `ipcMain.handle` whose first
parameter is `event` and whose body is not immediately guarded. Full data-flow
analysis is out of scope; the rule reports the pattern and the fix states what the
guard must check.

---

## Fuses: the switchboard compiled into the binary

Fuses are read from the executable itself, at a sentinel-delimited table. Nine exist;
the audit reports each one's state against its safe value.

| id | fuse | safe | why it matters |
| --- | --- | --- | --- |
| 0 | RunAsNode | disabled | `ELECTRON_RUN_AS_NODE=1` turns the app into a Node interpreter — attacker code runs with the app's identity and, on macOS, its TCC grants |
| 1 | EnableCookieEncryption | enabled | cookies at rest unencrypted are readable by any process that can read the profile |
| 2 | EnableNodeOptionsEnvironmentVariable | disabled | `NODE_OPTIONS` lets the environment inject `--require` |
| 3 | EnableNodeCliInspectArguments | disabled | `--inspect` opens a debugger port that executes arbitrary JS |
| 4 | EnableEmbeddedAsarIntegrityValidation | enabled | without it the archive can be swapped on disk |
| 5 | OnlyLoadAppFromAsar | enabled | without it a loose `app/` directory next to the archive wins |
| 6 | LoadBrowserProcessSpecificV8Snapshot | enabled | snapshot integrity |
| 7 | GrantFileProtocolExtraPrivileges | disabled | `file://` pages get extra capability |
| 8 | WasmTrapHandlers | enabled | trap handling hardening |

**A note on severity.** Fuse 4 and 5 are `critical` because they are the difference
between "an attacker needs to write to your install directory" and "an attacker who
can write to your install directory gets code execution on next launch". The other
criticals (`RunAsNode`) are critical because they need nothing but an environment
variable.

---

## Scoring

`penalty = Σ fuse weights + Σ rule weights`, then `score = 100 · e^(−penalty/90)`,
capped at 65 if any critical exists.

The exponential is deliberate. Linear subtraction puts a three-finding legacy app and
a twenty-finding modern app both at zero, and the number stops telling you anything.
The cap is deliberate too: an app that gives a renderer Node access is not "mostly
hardened" because it happens to be small.

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.

`not assessed` is separate from a low score. It means the tool could not read either
surface — usually a launcher stub rather than the real Electron binary. Treat it as
"unknown", never as "clean".
