---
name: invisible-char-audit
description: Find the characters a reviewer cannot see — bidirectional overrides that reorder source so the compiler reads different code than the diff shows, Unicode tag blocks that decode to instructions a model will follow while a human sees a blank, zero-width padding inside identifiers, Cyrillic and Greek homoglyphs that shadow a name, and space lookalikes that break string comparison. Reports codepoint, line and column; can strip the characters into a clean copy. Read-only by default. Use when reviewing untrusted code, a pasted snippet, a downloaded document, a PR from outside the team, or any text an agent is about to read.
license: MIT
---

# Invisible character audit

Some characters occupy no space. Bidi controls reorder a line without changing
its bytes. Tag characters encode ASCII and render as nothing at all. A zero-width
space splits an identifier while both halves still print as one word.

A human reviewing the diff sees clean code. The compiler, the interpreter, and
the language model see something else. This skill finds those characters and
tells you what they actually say.

No target is executed, imported, or rendered. The scanner reads bytes.

## When to use it

- Someone pastes a code snippet from a blog, a chat, or a model, and it "does
  not work" even though it looks identical to the working version.
- A pull request arrives from outside the team, or from an account you do not
  know well.
- You are about to let an agent read a document, a ticket, or a README that came
  from a third party.
- A package, a skill, or a config file was downloaded rather than written.
- A build fails with `SyntaxError` on a line that looks correct.
- A string comparison returns false for two strings that print the same.

## Run it

```bash
python scripts/audit.py ./some-repo
python scripts/audit.py ./notes.md --json
python scripts/audit.py ./src --markdown report.md
python scripts/audit.py ./src --ext py --ext js      # restrict by extension
python scripts/audit.py ./suspect.js --clean-out ./suspect.clean.js
python scripts/audit.py --explain U+202E
```

Point it at a file or a directory. Skips `node_modules`, `.git`, build output,
virtualenvs and binaries. Exit codes: `0` nothing at or above the threshold,
`1` findings, `2` target unreadable. `--fail-on critical|high|medium|low|none`
sets the gate (default `critical`).

`--clean-out` never overwrites its input. It writes a copy with the listed
characters removed and prints exactly what it removed:

```
wrote ./suspect.clean.js
  removed U+200B     ZERO WIDTH SPACE                           x2
  removed U+00AD     SOFT HYPHEN                                x1
```

`--explain` answers "what is this codepoint" without scanning anything.

## What it looks at

| id | class | severity | why it matters |
| --- | --- | --- | --- |
| IV-001 | Bidi controls (U+202A–U+202E, U+2066–U+2069) | critical | Trojan Source. Display order and parse order diverge. |
| IV-002 | Unicode tag block (U+E0020–U+E007F) | critical | Encodes ASCII, renders as nothing. Invisible instructions. |
| IV-003 | Zero-width, BOM mid-file, soft hyphen | medium–high | Splits tokens, defeats grep, breaks equality. |
| IV-004 | Space lookalikes (NBSP, thin, ideographic) | low–high | A copy-paste artifact that never equals U+0020. |
| IV-006 | Variation selectors outside emoji | medium | Invisible modifiers; pairs can carry data. |
| IV-007 | Raw C0/C1 control characters | high | No printable form; terminate strings, drive terminals. |
| IV-009 | Homoglyph inside an identifier | critical | `pаssword` with a Cyrillic `а` is a different name. |
| IV-010 | One identifier, several scripts | high | The impostor pattern: no real name mixes Latin and Cyrillic. |
| IV-011 | Non-ASCII hostname | low | Needs punycode; also where lookalikes live. |
| IV-012 | Hostname mixing Latin with lookalike scripts | critical | Typo-squat structure. Resolves elsewhere, reads as the brand. |
| IV-013 | UTF-16 file | medium | Rejected or mangled by toolchains; diffs as binary. |
| IV-014 | Invalid UTF-8 | medium | Content is an approximation; failed bytes may be deliberate. |

`references/checks.md` explains each class, the real-world incident behind it,
and the exact mechanism.

## The one that is not a classic

Bidi overrides have been known since Trojan Source (CVE-2021-42574). The tag
block is newer and less understood, and it is the reason this skill exists.

U+E0020 through U+E007F encode ASCII one to one, offset by 0xE0000. Every
mainstream renderer draws them as **nothing**. A language model reads them as
text. That asymmetry is the whole attack:

```
Release notes for version 2.1. Thanks to everyone who reported a bug.[35 invisible characters]

$ python scripts/audit.py ./release-notes.md
  [critical] IV-002  Invisible instructions hidden in Unicode tag characters
             at release-notes.md:5:39   U+E0020  TAG SPACE
             This line ends with 35 tag characters that render as nothing but
             decode to ASCII that a model will read:
             ' this sentence was invisible to you'
```

A reviewer sees an empty gap at the end of a sentence. An agent reading the same
file sees an instruction in plain ASCII. Nothing in the file is suspicious at a
glance, and no amount of "carefully review the diff" catches it, because there is
nothing to see.

The scanner does not just flag the run — it decodes it, so the payload is on
screen instead of being a warning about an unknown.

## Severity is decided by the container, not only by the character

A soft hyphen in a Markdown paragraph is a paste accident. The same byte inside a
Python identifier means the name you are reading is not the name the interpreter
resolves. So the base weight from the table is promoted in code and markup, and
demoted in prose.

Two suppressions exist because without them the tool was unusable:

- **U+3000 in a line that already contains CJK.** Full-width space is how Chinese
  and Japanese text is indented and aligned. Reporting it produced 62 findings on
  one resume template and buried everything else.
- **ZWJ, ZWNJ and U+FE0F inside an emoji sequence.** That is the joinery that
  makes a family emoji render as one glyph. Flagging it means the tool hates every
  README that uses an emoji.

Neither suppression is a general-purpose allowlist. Both are scoped to a visible
neighbour.

## Reading the result

`score 0–100` with a letter grade, capped at 55 while any critical finding stands.

Per-severity penalties are **capped** (`high` 60, `medium` 30, `low` 10; critical
uncapped). Without the caps, sixty correct-but-trivial low findings scored 13/100
— worse than a file with one live bidi override. Volume of small things must not
outweigh one dangerous thing.

`not assessed` is a real outcome: nothing readable was found.

## What it cannot do

- **It does not render the text.** It reads codepoints, so it tells you what the
  bytes are. It cannot tell you what a specific editor, terminal, or compiler
  version will draw or accept — those differ, and that is the attacker's room.
- **The homoglyph table is a curated subset**, not the full Unicode confusables
  list. It covers the letters that actually appear in impostors (Cyrillic, Greek,
  a handful of Latin lookalikes). A character absent from the table is not
  evidence of safety.
- **It does not diff two files for visual equivalence.** `--clean-out` gives you
  a clean copy; comparing it against the original is the reader's job.
- **It cannot judge intent.** A bidi control in a right-to-left localisation file
  is not an attack. The finding says "look here", not "this is malicious".

## What to avoid

- **Do not report the score without the characters.** "Grade F" means nothing to
  a developer. `U+202E at line 42` means everything.
- **Do not fix a file by hand after a hit.** There is usually a second character
  a few bytes away. Use `--clean-out` and diff it against the original.
- **Do not treat a clean scan as proof of safety.** It means none of the listed
  characters were found. Obfuscation has more mechanisms than this table.
- **Do not strip characters from a file you have not read.** If a tag block was
  hiding an instruction, what it said changes your response to the whole document.

## Files

- `scripts/audit.py` — CLI, walker, exit codes
- `scripts/detect.py` — the analyzers, severity by container, cleaning
- `scripts/chars.py` — character tables, each entry with its reason
- `scripts/report.py` — scoring and rendering
- `fixtures/build_fixtures.py` — regenerates the sample corpus from named codepoints
- `fixtures/vulnerable/` — six real techniques, one per file
- `fixtures/clean/` — Chinese, Arabic, emoji, accents: must score 100
- `references/checks.md` — every class, the incident behind it, the mechanism
