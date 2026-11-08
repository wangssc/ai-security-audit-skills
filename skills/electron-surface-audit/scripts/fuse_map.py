"""Electron fuses: binary layout, id map, and what each one actually buys an attacker.

The sentinel is a fixed 32-byte ASCII string that Electron's build bakes into the
binary right before the fuse table. Layout after the sentinel:

    offset  len  field
    +0      1    wire version (currently 1)
    +1      1    fuse count
    +2      2*n  [id, state] pairs, state is the ASCII byte '0' (disable),
                 '1' (enable) or '2' (remove)

The sentinel can appear more than once in a binary (Chromium embeds several
copies of build strings); we scan every occurrence and keep the table that
parses cleanly.
"""

from __future__ import annotations

SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"

STATE_DISABLE = 0x30  # '0'
STATE_ENABLE = 0x31   # '1'
STATE_REMOVE = 0x32   # '2'

STATE_NAME = {STATE_DISABLE: "disabled", STATE_ENABLE: "enabled", STATE_REMOVE: "removed"}

# Electron's Python-side equivalent of FuseV1Options. Do not reorder.
FUSES = [
    {
        "id": 0,
        "key": "RunAsNode",
        "label": "Run as Node",
        "safe_state": "disabled",
        "severity": "critical",
        "why": (
            "When enabled, the packaged executable still honours ELECTRON_RUN_AS_NODE, so anyone "
            "who can start the app can start a bare Node.js runtime instead. Any Node script then "
            "runs with the app's signing identity, its entitlements and its TCC grants -- screen "
            "recording, accessibility, full disk access. This is the single most used pivoting "
            "trick against signed Electron apps on macOS; the equivalent on Windows is 'just run "
            "node.exe', but a signed binary gets past application allow-lists."
        ),
        "fix": "--no-run-as-node (fuses CLI: RunAsNode=0)",
    },
    {
        "id": 1,
        "key": "EnableCookieEncryption",
        "label": "Cookie encryption",
        "safe_state": "enabled",
        "severity": "medium",
        "why": (
            "Off means the cookie store is written to disk as plaintext SQLite. Session tokens, "
            "CSRF cookies and 'remember me' secrets land in the profile directory where any "
            "backup tool, sync client or other local user process can read them. Only matters if "
            "the app keeps a session, which most do."
        ),
        "fix": "--enable-cookie-encryption (fuses CLI: EnableCookieEncryption=1)",
    },
    {
        "id": 2,
        "key": "EnableNodeOptionsEnvironmentVariable",
        "label": "NODE_OPTIONS support",
        "safe_state": "disabled",
        "severity": "high",
        "why": (
            "Honouring NODE_OPTIONS lets a launcher inject --require, --inspect or --max-old-space "
            "flags into the renderer's Node context. --require alone is arbitrary code execution "
            "inside the app process, with the app's privileges, before your first line runs."
        ),
        "fix": "--no-node-options (fuses CLI: EnableNodeOptionsEnvironmentVariable=0)",
    },
    {
        "id": 3,
        "key": "EnableNodeCliInspectArguments",
        "label": "--inspect arguments",
        "safe_state": "disabled",
        "severity": "high",
        "why": (
            "Accepts --inspect / --inspect-brk on the command line, which opens a V8 inspector "
            "port. Any local process can then attach, evaluate arbitrary JS in the main process "
            "and read every secret the app holds. Requires local access to the command line, so "
            "the practical risk is shared machines and anything that can spawn a process."
        ),
        "fix": "--no-node-cli-inspect (fuses CLI: EnableNodeCliInspectArguments=0)",
    },
    {
        "id": 4,
        "key": "EnableEmbeddedAsarIntegrityValidation",
        "label": "Embedded ASAR integrity",
        "safe_state": "enabled",
        "severity": "critical",
        "why": (
            "With this off there is nothing binding app.asar to the signed executable. An "
            "attacker who can write to the install directory swaps the archive for one that "
            "exfiltrates keystrokes or decrypts the local database. The code signature still "
            "verifies, because the signature covers the executable and the archive header, not "
            "the archive body. This is the difference between 'tampering needs a forged "
            "certificate' and 'tampering needs write access'."
        ),
        "fix": "--enable-embedded-asar-integrity-validation (fuses CLI: EnableEmbeddedAsarIntegrityValidation=1)",
    },
    {
        "id": 5,
        "key": "OnlyLoadAppFromAsar",
        "label": "Only load app from ASAR",
        "safe_state": "enabled",
        "severity": "critical",
        "why": (
            "If the app will also load from app/ or default_app, dropping a directory next to the "
            "executable can hijack startup without touching the signed binary at all. Combined "
            "with integrity validation this closes the 'side-load a folder' path completely; "
            "alone it still lets a writable install directory take over the app."
        ),
        "fix": "--only-load-app-from-asar (fuses CLI: OnlyLoadAppFromAsar=1)",
    },
    {
        "id": 6,
        "key": "LoadBrowserProcessSpecificV8Snapshot",
        "label": "Browser-specific V8 snapshot",
        "safe_state": "enabled",
        "severity": "low",
        "why": (
            "A separate V8 snapshot for the browser process narrows the blast radius when a "
            "renderer compromise is chained into the main process. Performance-motivated setting; "
            "the security delta is small."
        ),
        "fix": "--load-browser-process-specific-v8-snapshot (fuses CLI: LoadBrowserProcessSpecificV8Snapshot=1)",
    },
    {
        "id": 7,
        "key": "GrantFileProtocolExtraPrivileges",
        "label": "file:// extra privileges",
        "safe_state": "disabled",
        "severity": "high",
        "why": (
            "Restores the pre-Electron-5 behaviour where file:// pages get the same fetch and "
            "CORS exemptions as a privileged scheme. Any local HTML file loaded in a window -- "
            "a help page, a user-supplied document, a downloaded preview -- can then read local "
            "files and make cross-origin requests as if it were app code."
        ),
        "fix": "--no-grant-file-protocol-extra-privileges (fuses CLI: GrantFileProtocolExtraPrivileges=0)",
    },
    {
        "id": 8,
        "key": "WasmTrapHandlers",
        "label": "WASM trap handlers",
        "safe_state": "enabled",
        "severity": "low",
        "why": (
            "Hardening for WebAssembly trap handling. No direct attack narrative; keep the "
            "platform default."
        ),
        "fix": "leave at default",
    },
]

FUSE_BY_ID = {f["id"]: f for f in FUSES}
