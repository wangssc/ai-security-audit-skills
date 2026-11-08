# -*- coding: utf-8 -*-
"""Character tables.

Everything in this module is data, and every entry states why the character is
listed. A blacklist without a reason is unmaintainable: six months later nobody
can tell whether U+00AD was a considered decision or a leftover.

Three tables:

  INVISIBLE   characters that occupy no width, or move the caret, or reorder
              what follows. None of them belong in source code by accident.

  SPACES      characters that look like a space but are not U+0020. They break
              grep, break copy-paste into a terminal, and silently fail
              comparisons against a string literal.

  CONFUSABLES non-ASCII characters whose NFKC form is not ASCII but which a
              human reads as an ASCII letter. Used for homoglyph detection.

Severity rationale: a bidi override in a source file is an attack, not a typo.
A non-breaking space in a Markdown file is a typo, not an attack. The same
character therefore carries different weight depending on where it sits — that
decision is made in detect.py, not here.
"""

# --------------------------------------------------------------------------
# Invisible and directional control characters
# --------------------------------------------------------------------------

INVISIBLE = {
    "\u200b": ("ZERO WIDTH SPACE", "high",
               "Splits a token without changing how it looks. Defeats grep, and "
               "makes two identifiers that print identically compare unequal."),
    "\u200c": ("ZERO WIDTH NON-JOINER", "medium",
               "Legitimate in Persian and some Indic scripts. In Latin source it "
               "is almost always an accident or an obfuscation."),
    "\u200d": ("ZERO WIDTH JOINER", "medium",
               "Legitimate inside emoji sequences. In code it hides between "
               "identifiers and survives review."),
    "\u2060": ("WORD JOINER", "high",
               "Built to prevent line breaks, and to sit inside a word invisibly."),
    "\ufeff": ("ZERO WIDTH NO-BREAK SPACE / BOM", "high",
               "A byte-order mark is fine at offset 0. Anywhere else it is a "
               "character in the middle of your content that nothing renders."),
    "\u180e": ("MONGOLIAN VOWEL SEPARATOR", "medium",
               "Deprecated as whitespace, still zero-width in most engines."),
    "\u00ad": ("SOFT HYPHEN", "high",
               "Invisible unless a line breaks there. A string with a soft hyphen "
               "is never equal to the string you think you typed."),
    "\u034f": ("COMBINING GRAPHEME JOINER", "high",
               "Zero-width and combines with nothing. Pure padding."),
    "\u115f": ("HANGUL CHOSEONG FILLER", "medium",
               "Renders as blank in most Latin contexts."),
    "\u1160": ("HANGUL JUNGSEONG FILLER", "medium",
               "Same as above, trailing position."),
    "\u3164": ("HANGUL FILLER", "medium",
               "The classic 'invisible character' pasted into usernames."),
    "\uffa0": ("HALFWIDTH HANGUL FILLER", "medium",
               "Halfwidth blank. Same abuse as U+3164."),
}

# Bidi controls: CVE-2021-42574, "Trojan Source".
BIDI = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
    "\u061c": "ARABIC LETTER MARK",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
}

BIDI_WHY = (
    "Reorders how the line is displayed without changing the bytes the compiler "
    "reads. A reviewer sees a harmless comment; the compiler sees live code. This "
    "is the mechanism behind Trojan Source and it needs no other technique to hide "
    "a backdoor."
)

# Unicode Tag characters, U+E0000..U+E007F. Each one maps to an ASCII character
# and renders as nothing at all in every mainstream text renderer.
TAG_BASE = 0xE0000
TAG_FIRST = 0xE0020
TAG_LAST = 0xE007F
TAG_WHY = (
    "Tag characters encode ASCII one to one and have no visible glyph. A paragraph "
    "of them is invisible to a human, yet a language model reads the ASCII back and "
    "can follow it as instruction. This is the delivery mechanism for invisible "
    "prompt injection in documents, tickets, and README files."
)

# Variation selectors: only suspicious in code, expected after emoji.
VARIATION = set()
for _cp in list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0)):
    VARIATION.add(chr(_cp))

# --------------------------------------------------------------------------
# Space lookalikes
# --------------------------------------------------------------------------

SPACES = {
    "\u00a0": ("NO-BREAK SPACE", "Copied from a web page or a PDF. Never matches a "
                                  "literal space."),
    "\u2007": ("FIGURE SPACE", "Fixed width, not a space."),
    "\u202f": ("NARROW NO-BREAK SPACE", "Common in pasted units and currencies."),
    "\u2009": ("THIN SPACE", "Typesetting space; breaks simple string compares."),
    "\u200a": ("HAIR SPACE", "Same, thinner."),
    "\u3000": ("IDEOGRAPHIC SPACE", "Full-width space from CJK input methods."),
    "\u1680": ("OGHAM SPACE MARK", "Renders as a space, is not one."),
    "\u205f": ("MEDIUM MATHEMATICAL SPACE", "Math typesetting space."),
    "\u2028": ("LINE SEPARATOR", "Breaks lines in some parsers and not others."),
    "\u2029": ("PARAGRAPH SEPARATOR", "Same class of problem as U+2028."),
}

# --------------------------------------------------------------------------
# Homoglyphs. Curated on purpose: the Unicode confusables file is thousands of
# entries, most of which never appear in an identifier. These are the ones that
# actually turn up in typo-squats and in LLM-generated code that pasted a
# Cyrillic letter.
# --------------------------------------------------------------------------

CONFUSABLES = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u0501": "d", "\u04bb": "h", "\u04cf": "l", "\u051b": "q", "\u051d": "w",
    "\u043a": "k", "\u043c": "m", "\u043d": "h", "\u0442": "t", "\u0432": "b",
    "\u0433": "r", "\u044a": "b", "\u044c": "b",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0405": "S", "\u0406": "I", "\u0408": "J", "\u04ae": "Y",
    # Greek
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
    "\u03bd": "v", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
    "\u03b3": "y", "\u03b6": "z", "\u0391": "A", "\u0392": "B", "\u0395": "E",
    "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y",
    "\u03a7": "X",
    # Latin lookalikes that NFKC does not fold to ASCII
    "\u0131": "i", "\u0269": "i", "\u0268": "i", "\u0251": "a", "\u0261": "g",
    "\u029f": "l", "\u1d0f": "o", "\u1d1c": "u", "\u0299": "B",
}

# Deliberately absent: dashes, quotes and other punctuation that have ASCII
# lookalikes (U+2013, U+2019, U+2010 and friends). They are typography, not
# impostors — an en dash in "20–30K" is correct prose, and treating it as a
# homoglyph made the tool cry wolf on every document that uses ranges. Only
# letters can shadow a name, so only letters are listed.

# Script-name prefixes that unicodedata reports, mapped to a coarse script label.
SCRIPT_NAMES = {
    "LATIN": "Latin", "CYRILLIC": "Cyrillic", "GREEK": "Greek",
    "ARABIC": "Arabic", "HEBREW": "Hebrew", "HIRAGANA": "Kana",
    "KATAKANA": "Kana", "HANGUL": "Hangul", "CJK": "Han",
    "THAI": "Thai", "DEVANAGARI": "Devanagari",
}

# A URL or hostname with these scripts mixed together is a phishing signal, not
# a typo: no real brand mixes Latin and Cyrillic in one domain.
MIXED_SCRIPT_SUSPECT = {"Cyrillic", "Greek"}
