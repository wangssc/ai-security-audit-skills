# -*- coding: utf-8 -*-
"""Build the fixture corpus.

Every sample is generated from named codepoints rather than pasted, so the
bytes are reproducible and there is no mystery about what is inside them. Run
this to regenerate:  python fixtures/build_fixtures.py

vulnerable/  each file carries one real attack technique
clean/       legitimate non-ASCII that must NOT be reported
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
RLO = "\u202e"   # RIGHT-TO-LEFT OVERRIDE
LRI = "\u2066"   # LEFT-TO-RIGHT ISOLATE
PDI = "\u2069"   # POP DIRECTIONAL ISOLATE
LRO = "\u202d"
ZWSP = "\u200b"
ZWNJ = "\u200c"
ZWJ = "\u200d"
NBSP = "\u00a0"
IDEO_SP = "\u3000"
SOFT = "\u00ad"
TAG = lambda s: "".join(chr(0xE0000 + ord(c)) for c in s)


def write(rel, text):
    path = os.path.join(HERE, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


def build():
    made = []

    # --- Trojan Source: display order says one thing, the parser another -----
    made.append(write("vulnerable/trojan_source.js", (
        "// access control\n"
        "function check(user) {\n"
        "  if (user.role !== \"admin\" " + RLO + " ) { return false; } " + LRO + " // admin path\n"
        "  return true;\n"
        "}\n"
        "module.exports = check;\n"
    )))

    # --- Invisible instructions that a model reads and a human cannot ------
    # The payload is deliberately harmless. It demonstrates the channel — text
    # that renders as nothing and still reads as ASCII — without shipping an
    # actual instruction that a model might obey.
    made.append(write("vulnerable/hidden_instructions.md", (
        "# Release notes\n"
        "\n"
        "Version 2.1 fixes the caching bug reported last week.\n"
        "\n"
        "Thanks to everyone who filed a report."
        + TAG(" this sentence was invisible to you") + "\n"
    )))

    # --- Homoglyph in an identifier ---------------------------------------
    made.append(write("vulnerable/homoglyph.py", (
        "# py\n"
        "def check_p\u0430ssword(value):\n"
        "    return value == \"expected\"\n"
        "\n"
        "\n"
        "def login(user, value):\n"
        "    # calls the Cyrillic spelling above, not check_password\n"
        "    return check_p\u0430ssword(value)\n"
    )))

    # --- Zero-width padding inside a token --------------------------------
    made.append(write("vulnerable/zerowidth.txt", (
        "Set the pass" + ZWSP + "word before continuing.\n"
        "The API key is in \u200bconfig.json.\n"
        "Never commit a " + SOFT + "secret.\n"
    )))

    # --- Space lookalike that breaks a comparison -------------------------
    made.append(write("vulnerable/space_lookalike.py", (
        "# py\n"
        "ALLOWED = \"admin\"\n"
        "\n"
        "\n"
        "def is_admin(role):\n"
        "    # the literal on the next line contains a no-break space\n"
        "    return role == \"admin\u00a0\"\n"
        "\n"
        "\n"
        "INDENT = 1\n"
        "if INDENT:\n"
        "\u3000print(\"indented with an ideographic space\")\n"
    )))

    # --- Typo-squat hostname ---------------------------------------------
    made.append(write("vulnerable/typosquat.md", (
        "## Reset your password\n"
        "\n"
        "Visit https://\u0430pple.com/reset and sign in with your Apple ID.\n"
        "\n"
        "The link above uses CYRILLIC SMALL LETTER A, not the Latin one.\n"
    )))

    # --- Clean control: legitimate non-ASCII --------------------------------
    made.append(write("clean/notes.md", (
        "# 会议记录 / Meeting notes\n"
        "\n"
        "中文正文必须完全正常：我们今天讨论了缓存策略，以及下周的上线时间。\n"
        "Arabic: الاجتماع الأسبوع القادم لمناقشة الأداء. This is legitimate RTL.\n"
        "Accented Latin: café, naïve, Zürich, Straße.\n"
        "Emoji joinery: \U0001F468\u200d\U0001F469\u200d\U0001F467 and \u2764\ufe0f must not be flagged.\n"
        "Punctuation: 中文标点「」、；。and typographic quotes \u201cok\u201d.\n"
    )))

    made.append(write("clean/sample.py", (
        "# -*- coding: utf-8 -*-\n"
        "\"\"\"Legitimate file with non-ASCII content.\n"
        "\n"
        "Docstring contains \U0001F600 and a family emoji \U0001F468\u200d\U0001F469\u200d\U0001F467.\n"
        "\"\"\"\n"
        "\n"
        "GREETING = \"你好\"\n"
        "CURRENCY = \u20ac\n"
        "\n"
        "\n"
        "def greet(name):\n"
        "    return \"%s, %s\" % (GREETING, name)\n"
    )))

    return made


if __name__ == "__main__":
    for p in build():
        print(os.path.relpath(p, HERE).replace(os.sep, "/"))
