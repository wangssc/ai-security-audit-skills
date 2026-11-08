"""Static rules over an Electron app's JavaScript.

Every rule states what it looks for, why it matters, and what to change. Rules run
per line with comments stripped so documentation and dead examples do not raise
findings. Nothing here executes the target or resolves module graphs: these are
the checks an auditor can defend from source alone, which is the point.

Severity is about exploitability in a shipped app, not about how bad the API
sounds:

  critical  a remote page reaches Node, or an update can arrive unsigned
  high      a mitigation the platform offers is switched off
  medium    a mitigation is absent where the default would have been enough
  low       hardening gap with no direct path from untrusted input
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# comment stripping
# --------------------------------------------------------------------------- #

RE_LINE_COMMENT = re.compile(r"(?<![:'\"`\\])//.*$")
RE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def strip_comments(src: str) -> str:
    """Remove comments while leaving string literals intact.

    A full tokenizer would be better, but it also needs to know about template
    literals and regex bodies, and a wrong answer there produces false negatives
    on real code. This keeps newlines so reported line numbers stay honest.
    """
    out = []
    for line in src.splitlines():
        m = RE_LINE_COMMENT.search(line)
        if m:
            line = line[: m.start()]
        out.append(line)
    text = "\n".join(out)
    # Collapse block comments but keep the newline count.
    def _blank(m: re.Match) -> str:
        return "\n" * m.group(0).count("\n")
    return RE_BLOCK_COMMENT.sub(_blank, text)


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #

RULES: list[dict[str, Any]] = [
    {
        "id": "ES-001",
        "severity": "critical",
        "title": "nodeIntegration is enabled",
        "pattern": r"nodeIntegration\s*:\s*true",
        "scope": ("main", "preload", "renderer"),
        "why": "Any script that reaches this window can require('child_process') and run "
               "commands as the user. One XSS, one compromised ad frame, or one injected "
               "remote script becomes arbitrary code execution.",
        "fix": "Set nodeIntegration: false and move the privileged calls into a preload "
               "script that exposes a narrow, argument-validated API through contextBridge.",
        "ref": "Electron Security Checklist #2 Do not enable Node.js integration for remote content",
    },
    {
        "id": "ES-002",
        "severity": "critical",
        "title": "contextIsolation is disabled",
        "pattern": r"contextIsolation\s*:\s*false",
        "scope": ("main", "renderer"),
        "why": "Without isolation the preload script and the page share one JavaScript "
               "context, so page code can reach and rewrite whatever the preload put on "
               "window. contextBridge stops protecting anything at that point.",
        "fix": "Remove the option (isolation is the default since Electron 12) or set it to true.",
        "ref": "Electron Security Checklist #3 Enable Context Isolation",
    },
    {
        "id": "ES-003",
        "severity": "high",
        "title": "sandbox is disabled",
        "pattern": r"sandbox\s*:\s*false",
        "scope": ("main", "renderer"),
        "why": "A sandboxed renderer runs in a restricted process. Disabling it widens the "
               "blast radius of a renderer compromise from the renderer process to the "
               "whole user session.",
        "fix": "Remove sandbox: false. Preload scripts that need Node should be rewritten "
               "to use the limited subset available under the sandbox.",
        "ref": "Electron Security Checklist #4 Enable process sandboxing",
    },
    {
        "id": "ES-004",
        "severity": "critical",
        "title": "webSecurity is disabled",
        "pattern": r"webSecurity\s*:\s*false",
        "scope": ("main", "renderer"),
        "why": "This turns off the same-origin policy for the window: any page loaded there "
               "can read responses from any other origin, including authenticated ones.",
        "fix": "Remove the option. If a specific origin needs to be reached, proxy it through "
               "the main process and enforce an allowlist there.",
        "ref": "Electron Security Checklist #6 Do not disable webSecurity",
    },
    {
        "id": "ES-005",
        "severity": "high",
        "title": "allowRunningInsecureContent is enabled",
        "pattern": r"allowRunningInsecureContent\s*:\s*true",
        "scope": ("main", "renderer"),
        "why": "HTTPS pages may load and execute scripts over plain HTTP, which is exactly "
               "the position an on-path attacker needs to inject code.",
        "fix": "Remove the option and serve every subresource over TLS.",
        "ref": "Electron Security Checklist #7 Do not allow running insecure content",
    },
    {
        "id": "ES-006",
        "severity": "medium",
        "title": "experimentalFeatures is enabled",
        "pattern": r"experimentalFeatures\s*:\s*true",
        "scope": ("main", "renderer"),
        "why": "Unshipped Chromium features are not covered by the usual security review and "
               "have historically included escape hatches from renderer isolation.",
        "fix": "Remove the option unless a specific feature is required; document the reason "
               "in the code if it is.",
        "ref": "Electron Security Checklist #8 Do not enable experimental features",
    },
    {
        "id": "ES-007",
        "severity": "medium",
        "title": "enableBlinkFeatures is used",
        "pattern": r"enableBlinkFeatures\s*:",
        "scope": ("main", "renderer"),
        "why": "Selectively enabling Blink features exposes code paths that the default "
               "configuration deliberately leaves off.",
        "fix": "Drop the flag and check whether the behaviour is available behind a supported "
               "option instead.",
        "ref": "Electron Security Checklist #9 Do not use enableBlinkFeatures",
    },
    {
        "id": "ES-008",
        "severity": "high",
        "title": "Remote content loaded over plain HTTP",
        "pattern": r"""loadURL\(\s*['"`]http://(?!localhost|127\.0\.0\.1|\[::1\])""",
        "scope": ("main", "renderer"),
        "why": "A cleartext URL is not authenticated, so the content that ends up in the window "
               "is whatever the network hands over.",
        "fix": "Serve the app over HTTPS, or ship it inside the package and load with loadFile.",
        "ref": "Electron Security Checklist #1 Only load secure content",
    },
    {
        "id": "ES-009",
        "severity": "high",
        "title": "Remote content loaded into a privileged window",
        "pattern": r"""loadURL\(\s*['"`]https?://""",
        "scope": ("main",),
        "why": "Loading a remote origin means the app's own security now depends on a server "
               "you do not ship. Combined with any of the switches above it becomes remote "
               "code execution.",
        "fix": "Bundle the UI and load it with loadFile. If a remote origin is required, keep "
               "it in a window with nodeIntegration off, contextIsolation on, sandbox on, and "
               "a navigation allowlist.",
        "ref": "Electron Security Checklist #1 / #13 Limit navigation",
    },
    {
        "id": "ES-010",
        "severity": "medium",
        "title": "No Content-Security-Policy found",
        "pattern": r"__NEVER_MATCHES__",
        "scope": ("html",),
        "why": "Without a CSP the renderer has no second line of defence once markup injection "
               "happens; inline script and arbitrary remote script both stay available.",
        "fix": "Add a meta CSP with default-src 'self', no unsafe-inline, and an explicit "
               "script-src.",
        "ref": "Electron Security Checklist #7 / #6 Define a Content Security Policy",
    },
    {
        "id": "ES-011",
        "severity": "high",
        "title": "shell.openExternal called with a non-literal argument",
        "pattern": r"openExternal\(\s*(?!['\"`])[A-Za-z_$]",
        # A protocol/host check on the same statement or immediately above is the
        # mitigation this rule asks for, so a hit that already has one is not a
        # finding. Without this the rule fires on correct code and the report loses
        # credibility.
        "guard": r"(?:protocol\s*===?\s*['\"`]https?:|startsWith\(\s*['\"`]https?:|new URL\(|"
                 r"isAllowed|allowlist|allowList|ALLOWED_(?:HOST|ORIGIN|URL))",
        "scope": ("main", "preload", "renderer"),
        "why": "openExternal hands the string to the OS handler. With a URL taken from page "
               "content, file:// and custom-scheme payloads become a way to launch local "
               "programs or leak local files.",
        "fix": "Parse with new URL(), allow only http(s), compare the host against an allowlist, "
               "and reject everything else.",
        "ref": "Electron Security Checklist #15 Do not use shell.openExternal with untrusted content",
    },
    {
        "id": "ES-012",
        "severity": "high",
        "title": "ipcMain handler without sender validation",
        "pattern": r"ipcMain\.(?:on|handle)\(\s*['\"`][^'\"`]+['\"`]\s*,\s*(?:async\s*)?\(\s*(?:event|e)\b",
        "scope": ("main",),
        "why": "Any frame in any window of this app can send the channel, including one that "
               "ended up showing attacker-controlled content. A handler that trusts the message "
               "does privileged work on request.",
        "fix": "Validate event.senderFrame.url against the app's own origins before acting, and "
               "treat every payload field as untrusted input.",
        "ref": "Electron Security Checklist #17 Validate the sender of all IPC messages",
    },
    {
        "id": "ES-013",
        "severity": "medium",
        "title": "webview tag enabled",
        "pattern": r"webviewTag\s*:\s*true",
        "scope": ("main", "renderer"),
        "why": "A <webview> is a separate frame with its own preferences; a remote guest can be "
               "given more privilege than the host page if its attributes are not pinned.",
        "fix": "Prefer WebContentsView or an iframe. If webview stays, set allowpopups off and "
               "constrain the partition and preload.",
        "ref": "Electron Security Checklist #11 Verify WebView options",
    },
    {
        "id": "ES-014",
        "severity": "medium",
        "title": "New windows created without restriction",
        "pattern": r"setWindowOpenHandler\(\s*\(\s*\)\s*=>\s*\(\s*\{\s*action\s*:\s*['\"`]allow",
        "scope": ("main",),
        "why": "Allowing window.open to pass through lets page content decide where a new "
               "privileged window goes.",
        "fix": "Return { action: 'deny' } by default and open an external browser for links that "
               "must leave the app.",
        "ref": "Electron Security Checklist #14 Disable or limit creation of new windows",
    },
    {
        "id": "ES-015",
        "severity": "medium",
        "title": "will-navigate not restricted",
        "pattern": r"__NEVER_MATCHES__",
        "scope": ("main",),
        "why": "Without a will-navigate guard a link or a redirect can move the window to an "
               "origin the app never intended to trust.",
        "fix": "Handle will-navigate, compare the target against the app origin, and "
               "event.preventDefault() for anything else.",
        "ref": "Electron Security Checklist #13 Disable or limit navigation",
    },
    {
        "id": "ES-016",
        "severity": "high",
        "title": "Preload exposes a raw module to the page",
        "pattern": r"contextBridge\.exposeInMainWorld\([^)]*,\s*(?:require|electron|process|global)\b",
        "scope": ("preload",),
        "why": "Exposing require or the whole electron module gives page code the same reach as "
               "nodeIntegration, only spelled differently.",
        "fix": "Expose named functions with fixed signatures. Never pass a module object through.",
        "ref": "Electron Security Checklist #5 Do not expose Electron APIs to untrusted web content",
    },
    {
        "id": "ES-017",
        "severity": "medium",
        "title": "setPermissionRequestHandler is not set",
        "pattern": r"__NEVER_MATCHES__",
        "scope": ("main",),
        "why": "Camera, microphone, geolocation and notification requests are granted per the "
               "default policy. An app that never asked for them should not be able to obtain "
               "them because a page requested them.",
        "fix": "Call session.setPermissionRequestHandler and allow only the permissions the app "
               "actually implements.",
        "ref": "Electron Security Checklist #12 Handle session permission requests",
    },
    {
        "id": "ES-018",
        "severity": "high",
        "title": "Auto-updater trusts an unsigned feed",
        "pattern": r"setFeedURL\s*(?:\(|=)|autoUpdater\.feedURL\s*=|provider\s*:\s*['\"`]generic['\"`]",
        "scope": ("main",),
        "why": "If the update payload is fetched from a URL without signature verification, "
               "whoever controls that URL controls the code that runs at next launch.",
        "fix": "Use a provider with signed manifests, pin the signing key, and verify the "
               "downloaded artifact before it is applied.",
        "ref": "Electron Security Checklist #16 / update integrity",
    },
    {
        "id": "ES-019",
        "severity": "medium",
        "title": "Remote module enabled",
        "pattern": r"enableRemoteModule\s*:\s*true|@electron/remote",
        "scope": ("main", "preload", "renderer"),
        "why": "The remote module proxies main-process objects into the renderer. It was removed "
               "from core because that proxy is hard to keep safe.",
        "fix": "Replace with explicit IPC channels that the main process validates.",
        "ref": "Electron Security Checklist #5",
    },
    {
        "id": "ES-020",
        "severity": "low",
        "title": "DevTools opened in production",
        "pattern": r"openDevTools\(",
        "scope": ("main",),
        "why": "An attached DevTools session in a shipped build gives anyone at the machine a "
               "console inside the app's context.",
        "fix": "Gate it behind an environment check so it never runs in a release build.",
        "ref": "Electron Security Checklist #10",
    },
]

RULE_BY_ID = {r["id"]: r for r in RULES}

# Presence-style rules cannot be expressed as a single regex over one file, so they
# are checked against the whole source set by the caller.
PRESENCE_RULES = {
    "ES-010": {"needs": re.compile(r"Content-Security-Policy", re.I), "scope": ("html",)},
    "ES-015": {"needs": re.compile(r"will-navigate"), "scope": ("main",)},
    "ES-017": {"needs": re.compile(r"setPermissionRequestHandler"), "scope": ("main",)},
}


def _kind_of(path: str) -> str:
    low = path.lower()
    if low.endswith((".html", ".htm")):
        return "html"
    if "preload" in low:
        return "preload"
    return "main"


def scan_source(path: str, src: str) -> list[dict[str, Any]]:
    """Run every textual rule against one file."""
    kind = _kind_of(path)
    clean = strip_comments(src)
    lines = clean.splitlines()
    findings: list[dict[str, Any]] = []

    for rule in RULES:
        if rule["id"] in PRESENCE_RULES:
            continue
        if kind not in rule["scope"]:
            continue
        rx = re.compile(rule["pattern"])
        guard_rx = re.compile(rule["guard"], re.I) if rule.get("guard") else None
        for lineno, line in enumerate(lines, 1):
            m = rx.search(line)
            if not m:
                continue
            if guard_rx:
                # Look at the statement and the four lines above it: that is where a
                # URL guard lives in practice (`const u = new URL(x); if (...) ...`).
                window = "\n".join(lines[max(0, lineno - 5):lineno])
                if guard_rx.search(window):
                    findings.append({
                        "rule": rule["id"],
                        "severity": rule["severity"],
                        "title": rule["title"],
                        "file": path,
                        "line": lineno,
                        "excerpt": line.strip()[:200],
                        "why": rule["why"],
                        "fix": rule["fix"],
                        "ref": rule["ref"],
                        "suppressed": True,
                        "suppressed_by": "a URL guard appears in the same statement or the four lines above",
                    })
                    continue
            findings.append({
                "rule": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "file": path,
                "line": lineno,
                "excerpt": line.strip()[:200],
                "why": rule["why"],
                "fix": rule["fix"],
                "ref": rule["ref"],
                "suppressed": False,
            })
    return findings


def scan_presence(files: Iterable[tuple[str, str]], complete: bool = True) -> list[dict[str, Any]]:
    """Rules that fire on absence: evaluated once across the whole source set.

    `complete` says whether every candidate file was actually read. Absence is only
    evidence of absence when the scan covered everything, so a partial scan marks
    the result instead of asserting the mitigation is missing.
    """
    sources = [(p, strip_comments(s)) for p, s in files]
    findings: list[dict[str, Any]] = []
    for rid, spec in PRESENCE_RULES.items():
        rule = RULE_BY_ID[rid]
        relevant = [s for p, s in sources if _kind_of(p) in spec["scope"]]
        if not relevant:
            continue  # no main process / no html in scope, nothing to say
        if any(spec["needs"].search(s) for s in relevant):
            continue
        findings.append({
            "rule": rid,
            "severity": rule["severity"],
            "title": rule["title"],
            "file": "",
            "line": 0,
            "excerpt": "",
            "why": rule["why"],
            "fix": rule["fix"],
            "ref": rule["ref"],
            "suppressed": False,
            "partial_evidence": not complete,
        })
    return findings


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
