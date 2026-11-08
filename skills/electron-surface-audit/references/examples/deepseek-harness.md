# Electron surface audit

**Score 21/100 — grade F (critical)**

- target: `C:\Program Files\DeepSeek Harness\DeepSeek Harness.exe`
- executable: `C:\Program Files\DeepSeek Harness\DeepSeek Harness.exe`
- asar: `C:\Program Files\DeepSeek Harness\resources\app.asar`

Penalties: fuses 117, code 23

## Fuse state

| fuse | state | safe | verdict |
| --- | --- | --- | --- |
| Run as Node | enabled | disabled | RISK |
| Cookie encryption | disabled | enabled | RISK |
| NODE_OPTIONS support | enabled | disabled | RISK |
| --inspect arguments | enabled | disabled | RISK |
| Embedded ASAR integrity | disabled | enabled | RISK |
| Only load app from ASAR | disabled | enabled | RISK |
| Browser-specific V8 snapshot | disabled | enabled | RISK |
| file:// extra privileges | enabled | disabled | RISK |
| WASM trap handlers | enabled | enabled | ok |

## Findings

### ES-011 — shell.openExternal called with a non-literal argument

- severity: **high**
- where: `lib/main.js:10044`
- code: `} else await shell.openExternal(url);`
- why: openExternal hands the string to the OS handler. With a URL taken from page content, file:// and custom-scheme payloads become a way to launch local programs or leak local files.
- fix: Parse with new URL(), allow only http(s), compare the host against an allowlist, and reject everything else.
- reference: Electron Security Checklist #15 Do not use shell.openExternal with untrusted content

### ES-011 — shell.openExternal called with a non-literal argument

- severity: **high**
- where: `lib/main.js:12210`
- code: `shell.openExternal(platformLoginUrl(attempt.authorizeUrl)).catch(() => void 0);`
- why: openExternal hands the string to the OS handler. With a URL taken from page content, file:// and custom-scheme payloads become a way to launch local programs or leak local files.
- fix: Parse with new URL(), allow only http(s), compare the host against an allowlist, and reject everything else.
- reference: Electron Security Checklist #15 Do not use shell.openExternal with untrusted content

### ES-020 — DevTools opened in production

- severity: **low**
- where: `lib/main.js:10195`
- code: `contents.openDevTools({ mode: "detach" });`
- why: An attached DevTools session in a shipped build gives anyone at the machine a console inside the app's context.
- fix: Gate it behind an environment check so it never runs in a release build.
- reference: Electron Security Checklist #10

### ES-020 — DevTools opened in production

- severity: **low**
- where: `lib/main.js:12956`
- code: `if (activate && development && process.env.DSH_DESKTOP_OPEN_DEVTOOLS !== "0") window.webContents.openDevTools({ mode: "detach" });`
- why: An attached DevTools session in a shipped build gives anyone at the machine a console inside the app's context.
- fix: Gate it behind an environment check so it never runs in a release build.
- reference: Electron Security Checklist #10

### ES-020 — DevTools opened in production

- severity: **low**
- where: `lib/main.js:13182`
- code: `if (window !== void 0 && development && process.env.DSH_DESKTOP_OPEN_DEVTOOLS !== "0") window.webContents.openDevTools({ mode: "detach" });`
- why: An attached DevTools session in a shipped build gives anyone at the machine a console inside the app's context.
- fix: Gate it behind an environment check so it never runs in a release build.
- reference: Electron Security Checklist #10
