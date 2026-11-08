# -*- coding: utf-8 -*-
"""Legitimate file with non-ASCII content.

Docstring contains 😀 and a family emoji 👨‍👩‍👧.
"""

GREETING = "你好"
CURRENCY = €


def greet(name):
    return "%s, %s" % (GREETING, name)
