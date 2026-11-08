# The character classes, and the incident behind each

A table of "dangerous codepoints" is untrustworthy without the reason. Six months
later nobody can tell whether an entry was a considered decision or a leftover.
So each class below states the mechanism, what it was actually used for, and how
to verify a finding by hand.

---

## IV-001 — Bidirectional control characters

**Codepoints:** U+202A–U+202E (embedding and override), U+2066–U+2069 (isolate),
U+200E, U+200F, U+061C (marks).

**Mechanism.** The Unicode Bidirectional Algorithm decides the visual order of a
line from directional markers in the text. An override (`RLO`, U+202E) forces
every following character to be laid out right-to-left. The bytes never change.
Only the rendering does.

**Incident.** Trojan Source, disclosed by Nicholas Boucher and Ross Anderson in
2021, tracked as CVE-2021-42574. A comment containing an override can make the
rest of a line render as a comment while the parser still reads it as code — in
C, C++, C#, JavaScript, Python, Rust, and Go, because the attack targets the
editor and the review tool, not the compiler.

**Verified by hand.** `python -c "print(repr(open('f','rb').read()))"`, or
`cat -v`. Both will show `\u202e` where the editor shows nothing.

**Fix.** Strip all bidi controls from source. A project that genuinely needs
right-to-left text keeps it in data files, where it is content rather than
structure.

---

## IV-002 — Unicode tag characters

**Codepoints:** U+E0020–U+E007F. Each maps to ASCII by subtracting 0xE0000.

**Mechanism.** The tag block was added for deprecated language tags. Characters in
it have no glyph in any mainstream font, and text renderers skip them entirely.
They are, however, perfectly ordinary characters to a tokenizer. U+E0041 is
"TAG LATIN CAPITAL LETTER A" and encodes `A`.

**Why it matters now.** The asymmetry is new: the thing reading a document is
increasingly not a human. A paragraph of tag characters is invisible in every
editor, every diff, every review UI — and an instruction in plain ASCII to a
language model.

This class does not require the target to be naive. It requires only that
something read the file that renders nothing.

**Verified by hand.** `python -c "import sys; print([hex(ord(c)) for c in
open('f',encoding='utf-8').read() if 0xE0000 <= ord(c) <= 0xE007F])"`.

**Fix.** Delete the run. If it encoded an instruction, treat the whole source as
hostile and find out what else it carried — the visible text is not the payload.

---

## IV-003 — Zero-width and non-printing characters

**Codepoints:** U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 word joiner,
U+FEFF BOM (not at offset 0), U+00AD soft hyphen, U+034F CGJ, U+180E, Hangul
fillers U+115F/U+1160/U+3164/U+FFA0.

**Mechanism.** Two identifiers that print identically compare unequal. A
zero-width space inside `password` produces a name that looks right in every
editor and fails every grep. A soft hyphen makes a string literal permanently
different from the string you think you typed.

**Legitimate uses exist** and the scanner honours them: ZWJ joins emoji
sequences, ZWNJ is required in Persian and several Indic scripts, a BOM at offset
0 is a byte-order mark. Everything else is padding.

**Fix.** Delete. Re-type the line rather than editing it — a paste usually
carries more than one.

---

## IV-004 — Space lookalikes

**Codepoints:** U+00A0, U+2007, U+2009, U+200A, U+202F, U+3000, U+1680, U+205F,
U+2028, U+2029.

**Mechanism.** They render as a space and are not U+0020. A comparison against a
literal fails; indentation that looks consistent is not; a shell argument silently
becomes two.

**When it is correct:** U+3000 is standard for indentation and alignment in
Chinese and Japanese text. The scanner suppresses it on any line that already
contains CJK, because the alternative was 62 findings on one resume template.

**Fix.** Replace with U+0020, except in CJK typography where it belongs.

---

## IV-006 — Variation selectors

**Codepoints:** U+FE00–U+FE0F, U+E0100–U+E01EF.

**Mechanism.** Invisible modifiers that select a glyph variant. After an emoji
they are how emoji presentation works — U+FE0F is the difference between `❤` and
`❤️`, and it is what makes `1️⃣` a single keycap. Outside that context they carry
no meaning, and a run of them is a padding channel: each variation selector can
carry a few bits.

**Fix.** Remove outside emoji sequences; leave emoji joinery alone.

---

## IV-007 — Raw control characters

**Codepoints:** C0 (U+0000–U+001F except tab, newline, carriage return), DEL
(U+007F), C1 (U+0080–U+009F).

**Mechanism.** No printable form. In source they terminate strings early, split
tokens, or drive the terminal — a bare U+001B starts an escape sequence in
anything that prints the file.

**Fix.** Remove, or replace with an escape sequence if the value is intended.

---

## IV-009 / IV-010 — Homoglyphs and script mixing

**Mechanism.** Cyrillic `а`, `е`, `о`, `р`, `с`, `х` are pixel-identical to Latin
`a`, `e`, `o`, `p`, `c`, `x` in most fonts. A function named with one of them is
a different function. Shadowing a name this way defeats review and defeats grep,
because you search for the name you can see.

**Where it shows up:** typo-squatted package names, spoofed brand domains, and
code pasted from a source that substituted characters — including model output
that has "helpfully" transliterated.

**Detection here:** NFKC folding first (which resolves fullwidth and mathematical
alphanumerics), then a curated table for the Cyrillic, Greek and Latin lookalikes
that actually appear in impostors. Matching requires the character to be a
**letter**: an en dash is typography, not an impostor, and treating it as one made
every `20–30K` a critical finding.

**Fix.** Use the ASCII spelling. If a name is deliberately non-Latin, do not mix
it with Latin letters inside one token.

---

## IV-011 / IV-012 — Non-ASCII hostnames

**Mechanism.** An IDN resolving to a Cyrillic domain can render as a brand name.
`аpple.com` with U+0430 is a different registration from `apple.com`, and in a
browser address bar the two are indistinguishable.

**IV-012** fires when one hostname contains Latin letters *and* a lookalike
script together. No real brand does that. **IV-011** is the low-severity note for
any non-ASCII host: legitimate for many sites, and also where the fakes live.

**Fix.** Confirm the punycode form (`xn--...`) is the registration you intended.

---

## IV-013 / IV-014 — Encoding

**IV-013:** a UTF-16 file. Most toolchains reject or mangle it, and a diff tool
shows it as binary — which hides content from review as effectively as a tag
block.

**IV-014:** invalid UTF-8. The report is working from replacement characters, so
the content shown is an approximation. The bytes that failed are worth looking at
directly: malformed encoding is a cheap way to make a payload unreadable to a
scanner while remaining readable to a specific parser.

**Fix.** Establish the real encoding; if it is not UTF-8, convert and re-review.
