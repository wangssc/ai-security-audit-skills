# Electron surface audit

**Score 27/100 — grade F (critical)**

- target: `C:\Program Files\Typora\Typora.exe`
- executable: `C:\Program Files\Typora\Typora.exe`
- asar: `C:\Program Files\Typora\resources\app\atom.asar`

Penalties: fuses 0, code 117

## Fuse state

no valid fuse table (pre-fuse Electron build, or the sentinel was stripped)

## Findings

### ES-001 — nodeIntegration is enabled

- severity: **critical**
- where: `Downloader.js:20`
- code: `webPreferences: {nodeIntegration: true}`
- why: Any script that reaches this window can require('child_process') and run commands as the user. One XSS, one compromised ad frame, or one injected remote script becomes arbitrary code execution.
- fix: Set nodeIntegration: false and move the privileged calls into a preload script that exposes a narrow, argument-validated API through contextBridge.
- reference: Electron Security Checklist #2 Do not enable Node.js integration for remote content

### ES-001 — nodeIntegration is enabled

- severity: **critical**
- where: `updater.js:109`
- code: `nodeIntegration: true,`
- why: Any script that reaches this window can require('child_process') and run commands as the user. One XSS, one compromised ad frame, or one injected remote script becomes arbitrary code execution.
- fix: Set nodeIntegration: false and move the privileged calls into a preload script that exposes a narrow, argument-validated API through contextBridge.
- reference: Electron Security Checklist #2 Do not enable Node.js integration for remote content

### ES-001 — nodeIntegration is enabled

- severity: **critical**
- where: `updater.js:149`
- code: `webPreferences: {nodeIntegration: true}`
- why: Any script that reaches this window can require('child_process') and run commands as the user. One XSS, one compromised ad frame, or one injected remote script becomes arbitrary code execution.
- fix: Set nodeIntegration: false and move the privileged calls into a preload script that exposes a narrow, argument-validated API through contextBridge.
- reference: Electron Security Checklist #2 Do not enable Node.js integration for remote content

### ES-011 — shell.openExternal called with a non-literal argument

- severity: **high**
- where: `Desktop.js:63`
- code: `return electron.shell.openExternal(url);`
- why: openExternal hands the string to the OS handler. With a URL taken from page content, file:// and custom-scheme payloads become a way to launch local programs or leak local files.
- fix: Parse with new URL(), allow only http(s), compare the host against an allowlist, and reject everything else.
- reference: Electron Security Checklist #15 Do not use shell.openExternal with untrusted content

### ES-011 — shell.openExternal called with a non-literal argument

- severity: **high**
- where: `WindowController.js:158`
- code: `shell.openExternal(url);`
- why: openExternal hands the string to the OS handler. With a URL taken from page content, file:// and custom-scheme payloads become a way to launch local programs or leak local files.
- fix: Parse with new URL(), allow only http(s), compare the host against an allowlist, and reject everything else.
- reference: Electron Security Checklist #15 Do not use shell.openExternal with untrusted content

### ES-011 — shell.openExternal called with a non-literal argument

- severity: **high**
- where: `WindowController.js:162`
- code: `shell.openExternal(url);`
- why: openExternal hands the string to the OS handler. With a URL taken from page content, file:// and custom-scheme payloads become a way to launch local programs or leak local files.
- fix: Parse with new URL(), allow only http(s), compare the host against an allowlist, and reject everything else.
- reference: Electron Security Checklist #15 Do not use shell.openExternal with untrusted content

### ES-011 — shell.openExternal called with a non-literal argument

- severity: **high**
- where: `updater.js:131`
- code: `electron.shell.openExternal(url);`
- why: openExternal hands the string to the OS handler. With a URL taken from page content, file:// and custom-scheme payloads become a way to launch local programs or leak local files.
- fix: Parse with new URL(), allow only http(s), compare the host against an allowlist, and reject everything else.
- reference: Electron Security Checklist #15 Do not use shell.openExternal with untrusted content

### ES-018 — Auto-updater trusts an unsigned feed

- severity: **high**
- where: `updater.js:88`
- code: `updater.setFeedURL = function(url){`
- why: If the update payload is fetched from a URL without signature verification, whoever controls that URL controls the code that runs at next launch.
- fix: Use a provider with signed manifests, pin the signing key, and verify the downloaded artifact before it is applied.
- reference: Electron Security Checklist #16 / update integrity

### ES-017 — setPermissionRequestHandler is not set

- severity: **medium**
- where: absence check
- why: Camera, microphone, geolocation and notification requests are granted per the default policy. An app that never asked for them should not be able to obtain them because a page requested them.
- fix: Call session.setPermissionRequestHandler and allow only the permissions the app actually implements.
- reference: Electron Security Checklist #12 Handle session permission requests

### ES-020 — DevTools opened in production

- severity: **low**
- where: `WindowController.js:96`
- code: `win.webContents.openDevTools();`
- why: An attached DevTools session in a shipped build gives anyone at the machine a console inside the app's context.
- fix: Gate it behind an environment check so it never runs in a release build.
- reference: Electron Security Checklist #10

### ES-020 — DevTools opened in production

- severity: **low**
- where: `menu.js:1392`
- code: `focusedWindow.webContents.openDevTools();`
- why: An attached DevTools session in a shipped build gives anyone at the machine a console inside the app's context.
- fix: Gate it behind an environment check so it never runs in a release build.
- reference: Electron Security Checklist #10

## Coverage limits

- No fuse table: this is a pre-fuse Electron build (< 12) or a non-Electron executable. Fuse-level hardening cannot be assessed; treat every fuse as unset.
