# -*- coding: utf-8 -*-
"""Detection.

The scanner reads bytes and never writes, runs, or evaluates the target. That
is the same constraint the rest of the toolchain keeps, and it matters more here
than usual: the thing being inspected is literally built to be misread.

Severity depends on the container, not only on the character. A soft hyphen in
a Markdown paragraph is a copy-paste accident. The same byte inside a Python
identifier means the name you are reading is not the name the interpreter sees.
So each table entry carries a base weight, and the container promotes or demotes
it.
"""

import re
import unicodedata

import chars as C

CODE_EXTS = {
    "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "go", "rs", "java", "kt",
    "c", "h", "cc", "cpp", "hpp", "cs", "rb", "php", "swift", "scala", "sh",
    "bash", "zsh", "ps1", "bat", "sql", "css", "scss", "lua", "pl", "r",
}
MARKUP_EXTS = {"html", "htm", "xml", "vue", "svelte"}
TEXT_EXTS = {
    "md", "markdown", "txt", "rst", "prompt", "json", "yaml", "yml", "toml",
    "ini", "cfg", "env", "csv", "tsv", "log", "srt", "vtt",
}

SEV_ORDER = ["critical", "high", "medium", "low"]

IDENT = re.compile(r"[A-Za-z0-9_\u0080-\U0010FFFF]+")
URL = re.compile(r"(?:https?://|www\.)([^\s/\"'<>()\[\]]+)")
EMAILISH = re.compile(r"[\w.\-+]+@([\w.\-]+\.[A-Za-z]{2,})")


def container(path, ext):
    if ext in CODE_EXTS:
        return "code"
    if ext in MARKUP_EXTS:
        return "markup"
    if ext in TEXT_EXTS:
        return "text"
    return "text"


def _promote(sev, kind):
    """Container-aware severity."""
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    idx = order.get(sev, 2)
    if kind == "code" and sev in ("medium", "low"):
        idx = max(0, idx - 1)      # a stray invisible char in code is worse
    elif kind == "text" and sev == "high":
        idx = min(3, idx + 1)      # in prose it is usually a paste accident
    return SEV_ORDER[idx]


def decode(raw):
    """Return (text, encoding-finding-or-None)."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        for enc in ("utf-16",):
            try:
                return raw.decode(enc), {
                    "id": "IV-013", "severity": "medium",
                    "title": "File is UTF-16, not UTF-8",
                    "detail": "A UTF-16 source file is rejected or mangled by most "
                              "toolchains, and a diff tool will show it as binary. "
                              "The encoding itself hides content from review.",
                    "fix": "Re-encode as UTF-8 without BOM.",
                }
            except UnicodeDecodeError:
                break
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace"), {
            "id": "IV-014", "severity": "medium",
            "title": "File is not valid UTF-8",
            "detail": "Invalid byte sequences were replaced with U+FFFD, so the "
                      "content below is an approximation. The bytes that failed may "
                      "be an obfuscation attempt.",
            "fix": "Determine the real encoding; if it is not UTF-8, convert it.",
        }


def _cp(ch):
    return "U+%04X" % ord(ch)


def _name(ch):
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "UNNAMED"


def _skeleton(ch):
    """ASCII lookalike for this character, or None.

    Only letters qualify. A name can be shadowed by a Cyrillic 'а'; it cannot be
    shadowed by an en dash, because punctuation is not part of an identifier.
    Gating on the Unicode category is what keeps ranges like "20–30K" out of the
    report.
    """
    if ord(ch) < 128:
        return None
    if not unicodedata.category(ch).startswith("L"):
        return None
    folded = unicodedata.normalize("NFKC", ch)
    if len(folded) == 1 and ord(folded) < 128 and folded.isalpha():
        return folded
    return C.CONFUSABLES.get(ch)


def _script(ch):
    try:
        return C.SCRIPT_NAMES.get(unicodedata.name(ch).split(" ")[0], None)
    except ValueError:
        return None


def _mk(fid, sev, title, path, line, col, ch, detail, fix):
    return {
        "id": fid, "severity": sev, "title": title, "path": path,
        "line": line, "col": col,
        "codepoint": _cp(ch) if ch else None,
        "name": _name(ch) if ch else None,
        "char": ("'%s'" % ch) if ch and ch.isprintable() else (repr(ch) if ch else None),
        "detail": detail, "fix": fix,
    }


def _tag_payload(chars):
    """Tag characters encode ASCII as cp - 0xE0000."""
    out = []
    for ch in chars:
        cp = ord(ch)
        if C.TAG_FIRST <= cp <= C.TAG_LAST:
            out.append(chr(cp - C.TAG_BASE))
    return "".join(out)


EMOJI_RANGES = ((0x1F000, 0x1FAFF), (0x2600, 0x27BF), (0x2B00, 0x2BFF),
                (0xFE0F, 0xFE0F), (0x1F1E6, 0x1F1FF), (0x2190, 0x21FF),
                (0x2700, 0x27BF), (0x1F3FB, 0x1F3FF),
                (0x20E3, 0x20E3))  # COMBINING ENCLOSING KEYCAP: 1️⃣ is a sequence


CJK_RANGES = ((0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0x3040, 0x30FF),
              (0xAC00, 0xD7AF), (0xF900, 0xFAFF))


def _has_cjk(line):
    for ch in line:
        cp = ord(ch)
        for lo, hi in CJK_RANGES:
            if lo <= cp <= hi:
                return True
    return False


def _near_emoji(line, i):
    """True when the character at i sits inside an emoji sequence.

    ZWJ and the variation selectors are the joinery that makes a family emoji
    render as one glyph. Flagging them in prose would be the fastest way to make
    this tool hate every README that uses an emoji.
    """
    for j in (i - 1, i + 1):
        if 0 <= j < len(line):
            cp = ord(line[j])
            for lo, hi in EMOJI_RANGES:
                if lo <= cp <= hi:
                    return True
    return False


def analyze(text, path, ext):
    kind = container(path, ext)
    findings = []
    lines = text.split("\n")
    seen = set()

    def add(key, item):
        if key in seen:
            return
        seen.add(key)
        findings.append(item)

    for lineno, line in enumerate(lines, 1):
        # --- runs of tag characters: decode the payload, one finding per run
        run, run_start = [], None
        for i, ch in enumerate(line):
            cp = ord(ch)
            if C.TAG_FIRST <= cp <= C.TAG_LAST:
                if not run:
                    run_start = i
                run.append(ch)
            elif run:
                payload = _tag_payload(run)
                add(("tag", lineno, run_start), _mk(
                    "IV-002", "critical",
                    "Invisible instructions hidden in Unicode tag characters",
                    path, lineno, run_start + 1, run[0],
                    "This line contains %d tag characters that render as nothing but "
                    "decode to ASCII that a model will read: %r. A human reviewing "
                    "this text sees an empty gap. "
                    % (len(run), payload[:120]),
                    "Delete the tag characters. If the text came from a third party, "
                    "treat it as hostile input and find out what else it contained."))
                run, run_start = [], None
        if run:
            payload = _tag_payload(run)
            add(("tag", lineno, run_start), _mk(
                "IV-002", "critical",
                "Invisible instructions hidden in Unicode tag characters",
                path, lineno, run_start + 1, run[0],
                "This line ends with %d tag characters that render as nothing but "
                "decode to ASCII that a model will read: %r. "
                % (len(run), payload[:120]),
                "Delete the tag characters."))

        for col, ch in enumerate(line):
            cp = ord(ch)

            # --- bidi controls -------------------------------------------------
            if ch in C.BIDI:
                add(("bidi", lineno, col), _mk(
                    "IV-001", "critical" if kind != "text" else "high",
                    "Bidirectional control character",
                    path, lineno, col + 1, ch,
                    "%s. %s" % (C.BIDI[ch], C.BIDI_WHY),
                    "Strip all bidi controls from source. If the project genuinely "
                    "needs right-to-left text, keep it in data files, not in code."))
                continue

            # --- variation selectors ------------------------------------------
            if ch in C.VARIATION:
                if _near_emoji(line, col):
                    continue  # U+FE0F after an emoji is how emoji presentation works
                if kind in ("code", "markup"):
                    add(("vs", lineno, col), _mk(
                        "IV-006", "medium",
                        "Variation selector outside an emoji",
                        path, lineno, col + 1, ch,
                        "Variation selectors are invisible modifiers. Outside emoji "
                        "they carry no meaning, and in pairs they can encode data.",
                        "Remove it, or confirm it is part of a deliberate emoji."))
                continue

            # --- invisible / zero width ---------------------------------------
            if ch in C.INVISIBLE:
                label, base, why = C.INVISIBLE[ch]
                if cp == 0xFEFF and lineno == 1 and col == 0:
                    continue  # a leading BOM is fine
                if cp in (0x200C, 0x200D, 0xFE0F) and _near_emoji(line, col):
                    continue  # emoji joinery, not padding
                add(("inv", lineno, col), _mk(
                    "IV-003", _promote(base, kind),
                    "Invisible character: " + label,
                    path, lineno, col + 1, ch, why,
                    "Delete the character. If it was pasted in, re-type the line "
                    "rather than fixing it by hand — there is often a second one."))
                continue

            # --- space lookalikes ---------------------------------------------
            if ch in C.SPACES:
                label, why = C.SPACES[ch]
                # U+3000 is how Chinese and Japanese text is indented and
                # aligned. In a line that already contains CJK it is correct
                # typography, not a lookalike — reporting it produced 62 findings
                # on one resume template and buried everything else.
                if cp == 0x3000 and _has_cjk(line):
                    continue
                sev = "high" if kind == "code" else "low"
                add(("sp", lineno, col), _mk(
                    "IV-004", sev,
                    "Space lookalike: " + label,
                    path, lineno, col + 1, ch, why,
                    "Replace with U+0020. In code this breaks string comparison and "
                    "indentation without changing how the line looks."))
                continue

            # --- other control characters -------------------------------------
            if (cp < 0x20 and ch not in "\t\r") or cp == 0x7F or (0x80 <= cp <= 0x9F):
                add(("ctl", lineno, col), _mk(
                    "IV-007", "high",
                    "Raw control character in content",
                    path, lineno, col + 1, ch,
                    "Control characters have no printable form. In a source file they "
                    "terminate strings, split tokens, or drive the terminal.",
                    "Remove it and use an escape sequence if the value is intended."))
                continue

        # --- identifiers: homoglyphs and script mixing ------------------------
        if kind in ("code", "markup", "text"):
            for m in IDENT.finditer(line):
                token = m.group(0)
                if token.isascii():
                    continue
                has_ascii_letter = any(c.isascii() and c.isalpha() for c in token)
                scripts = set()
                first_homoglyph = None
                for off, ch in enumerate(token):
                    s = _script(ch)
                    if s:
                        scripts.add(s)
                    sk = _skeleton(ch)
                    if sk and first_homoglyph is None:
                        first_homoglyph = (off, ch, sk)
                col = m.start() + 1

                if first_homoglyph and has_ascii_letter:
                    off, ch, sk = first_homoglyph
                    add(("homo", lineno, m.start()), _mk(
                        "IV-009", "critical" if kind == "code" else "high",
                        "Homoglyph inside an identifier",
                        path, lineno, col + off, ch,
                        "'%s' renders as '%s' but is %s. The token reads as '%s' and "
                        "is not it. Two identifiers that print identically can be "
                        "two different names — the classic way to shadow a function "
                        "or a package."
                        % (ch, sk, _name(ch), token),
                        "Use the ASCII spelling. If the name is meant to be "
                        "non-Latin, do not mix it with Latin letters in one token."))

                if label_mixed(scripts):
                    add(("mix", lineno, m.start()), _mk(
                        "IV-010", "high",
                        "One identifier, several scripts",
                        path, lineno, col, token[0],
                        "'%s' mixes %s in a single token. Real identifiers do not; "
                        "impostors do." % (token, ", ".join(sorted(scripts))),
                        "Rename using one script only."))

        # --- URLs and hostnames ----------------------------------------------
        if kind in ("markup", "text", "code"):
            for m in URL.finditer(line):
                host = m.group(1).split(":")[0]
                if host.isascii():
                    continue
                scripts = {s for s in (_script(c) for c in host) if s}
                if scripts & C.MIXED_SCRIPT_SUSPECT:
                    add(("host", lineno, m.start(1)), _mk(
                        "IV-012", "critical",
                        "Hostname mixes Latin with lookalike scripts",
                        path, lineno, m.start(1) + 1, host[0],
                        "The host '%s' contains %s next to Latin letters. This is the "
                        "structure of a typo-squat: it resolves somewhere different "
                        "while reading as the name you expect."
                        % (host, ", ".join(sorted(scripts))),
                        "Replace with the ASCII or punycode form and verify the "
                        "registrant before trusting it."))
                else:
                    add(("host2", lineno, m.start(1)), _mk(
                        "IV-011", "low",
                        "Non-ASCII hostname",
                        path, lineno, m.start(1) + 1, host[0],
                        "The host '%s' needs IDN/punycode handling. Legitimate for "
                        "many sites, but it is also where lookalikes live." % host,
                        "Confirm the punycode form is the domain you intended."))

    return findings


def label_mixed(scripts):
    """Latin plus a lookalike script in one token is the impostor pattern."""
    if len(scripts) < 2:
        return False
    return "Latin" in scripts and bool(scripts & C.MIXED_SCRIPT_SUSPECT)


# --------------------------------------------------------------------------
# Cleaning
# --------------------------------------------------------------------------

def strip(text):
    """Return (cleaned, removed) where removed is a list of (char, count)."""
    from collections import Counter
    counts = Counter()
    out = []
    for ch in text:
        cp = ord(ch)
        drop = (
            ch in C.BIDI
            or ch in C.SPACES
            or (ch in C.INVISIBLE and cp != 0xFEFF)
            or C.TAG_FIRST <= cp <= C.TAG_LAST
            or ch in C.VARIATION
            or (cp < 0x20 and ch not in "\t\n\r")
            or cp == 0x7F
        )
        if ch in C.SPACES:
            out.append(" ")
            counts[ch] += 1
        elif drop:
            counts[ch] += 1
        else:
            out.append(ch)
    return "".join(out), counts.most_common()
