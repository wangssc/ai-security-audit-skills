# -*- coding: utf-8 -*-
"""The two detectors that a line regex cannot do honestly.

LAI-101 (prompt concatenation) and LAI-109 (unfiltered retrieval) are the two
findings that actually matter, and both are relational: the danger is not the
presence of an f-string, it is that a specific untrusted name reached a string
that is used as an instruction. Matching `{...}` alone flags every log line in
the codebase, which is how a scanner loses its reader.

So these read the file with a little structure: a string-literal lexer, brace
extraction, and parenthesis matching for call arguments. Still no execution, no
imports, no parsing library — just enough shape to tell an instruction from a
log message.
"""

import re

import rules as R

IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

STRING_LITERAL = re.compile(
    r"(?P<prefix>[rbfuRBFU]{0,2})(?P<q>\"\"\"|'''|\"|')"
    r"(?P<body>(?:\\.|[\s\S])*?)(?P=q)",
    re.MULTILINE,
)

BRACE_EXPR = re.compile(r"\{([^{}\n]{1,200})\}")

# A string is being used as an instruction when the assignment target or the
# literal text itself says so.
PROMPT_TARGET = re.compile(
    r"\b(prompts?|system|sys_prompt|sysprompt|instruction|instructions"
    r"|template|messages|msg_list|chat_prompt|final_prompt|prompt_text"
    r"|full_prompt|system_message|user_message|content)\b\s*"
    r"(\+?=|\.append\s*\(|\.format\s*\(|:)",
    re.IGNORECASE,
)

PROMPT_WORDS = re.compile(
    r"(you are|you must|your task|your role|as an? (ai|assistant)"
    r"|system prompt|instructions?:|do not|must not|respond (only )?with"
    r"|answer (only )?in|return json|你是|你的角色|你的任务|请作为|扮演"
    r"|回答|回复|不得|必须|规则)",
    re.IGNORECASE,
)

RETRIEVAL_CALL = re.compile(
    r"(similarity_search(?:_with_score)?|get_relevant_documents|max_marginal_relevance"
    r"|vectorstore\.\w+|vector_store\.\w+|collection\.query|index\.search"
    r"|search_index|nearest_neighbou?rs?)",
    re.IGNORECASE,
)

FILTER_TERMS = re.compile(
    r"(filter\s*=|filters\s*=|where\s*=|where_document|tenant|org_id|organization_id"
    r"|user_id|workspace_id|namespace|partition|metadata_filter|acl|permission"
    r"|security_filter|allowed_ids|owner_id|account_id)",
    re.IGNORECASE,
)


def _line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def _snippet(line, limit=200):
    s = line.strip()
    return s[:limit] + ("..." if len(s) > limit else "")


def _identifiers(expr):
    return {m.group(1).lower() for m in IDENT.finditer(expr or "")}


def _is_untrusted(expr):
    names = _identifiers(expr)
    for n in names:
        if n in R.UNTRUSTED_NAMES:
            return True
        # userInput / req.body / request.json(...) style access
        if re.match(r"^(userinput|re(quest|q)?body|requestjson|queryparams)$", n):
            return True
    return False


def _matching_paren(text, open_idx, limit=2000):
    """Return the index just past the closing paren, or None."""
    depth = 0
    i = open_idx
    end = min(len(text), open_idx + limit)
    quote = None
    esc = False
    while i < end:
        ch = text[i]
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif quote:
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def detect_prompt_concat(ctx):
    """LAI-101: an untrusted name reached a string used as an instruction."""
    if not re.search(R.MODEL_CALL, ctx.code, re.IGNORECASE):
        return []
    rule = R.CUSTOM_RULES["LAI-101"]
    findings = []
    seen_lines = set()

    for m in STRING_LITERAL.finditer(ctx.code):
        body = m.group("body")
        start = m.start()
        line_no = _line_of(ctx.code, start)
        if line_no in seen_lines:
            continue

        line_start = ctx.code.rfind("\n", 0, start) + 1
        probe = ctx.code[max(0, line_start - 400): start + len(m.group(0)) + 400]

        if not (PROMPT_WORDS.search(body) or PROMPT_TARGET.search(probe)):
            continue

        hit_expr = None
        for bm in BRACE_EXPR.finditer(body):
            if _is_untrusted(bm.group(1)):
                hit_expr = bm.group(1).strip()
                break

        if hit_expr is None:
            tail = ctx.code[m.end(): m.end() + 300]
            fm = re.match(r"\s*\.\s*format\s*\((.*?)\)", tail, re.DOTALL)
            if fm and _is_untrusted(fm.group(1)):
                hit_expr = fm.group(1).strip()[:80]
            else:
                pm = re.match(r"\s*%\s*\(?([^)\n]{1,120})", tail)
                if pm and _is_untrusted(pm.group(1)):
                    hit_expr = pm.group(1).strip()
                else:
                    plus = re.match(r"\s*\+\s*([A-Za-z_][A-Za-z0-9_\.]*)", tail)
                    if plus and _is_untrusted(plus.group(1)):
                        hit_expr = plus.group(1)

        if hit_expr is None:
            continue

        raw_line = ctx.text.split("\n")[line_no - 1] if line_no - 1 < len(ctx.text.split("\n")) else ""
        if re.search(r"(sanitiz|escape|fence|wrap_|redact|injection)", raw_line, re.I):
            continue

        seen_lines.add(line_no)
        findings.append({
            "id": rule["id"],
            "severity": rule["severity"],
            "title": rule["title"],
            "owasp": rule["owasp"],
            "why": rule["why"],
            "fix": rule["fix"],
            "path": ctx.rel,
            "line": line_no,
            "snippet": _snippet("%s  <<  %s" % (raw_line, hit_expr)),
            "kind": "flow",
        })
        if len(findings) >= 3:
            break

    return findings


def detect_retrieval_filter(ctx, project_has_model=False):
    """LAI-109: a retrieval call whose candidates are not narrowed by identity.

    Gated on the project actually calling a model. A plain SQL reporting tool
    that happens to use a search index has no prompt to poison, and reporting it
    here would be the kind of false positive that makes the rest of the report
    worthless.
    """
    rule = R.CUSTOM_RULES["LAI-109"]
    if not project_has_model:
        return []
    if not re.search(R.DRETRIEVAL, ctx.code, re.IGNORECASE):
        return []
    findings = []
    seen = set()

    for m in RETRIEVAL_CALL.finditer(ctx.code):
        open_idx = ctx.code.find("(", m.end() - 1)
        if open_idx == -1 or m.end() - 1 - open_idx > 2:
            open_idx = ctx.code.find("(", m.end())
        if open_idx == -1:
            continue
        close_idx = _matching_paren(ctx.code, open_idx)
        call = ctx.code[m.start(): close_idx] if close_idx else ctx.code[m.start(): m.start() + 300]

        line_no = _line_of(ctx.code, m.start())
        if line_no in seen:
            continue

        if FILTER_TERMS.search(call):
            continue

        # The filter is often applied by a wrapper defined elsewhere; look at the
        # surrounding block before calling it exposed.
        lo = ctx.code.rfind("\n\n", 0, m.start())
        hi = ctx.code.find("\n\n", close_idx or m.end())
        block = ctx.code[max(0, lo): hi if hi != -1 else m.end() + 200]
        if FILTER_TERMS.search(block):
            continue

        seen.add(line_no)
        raw_line = ctx.text.split("\n")[line_no - 1] if line_no - 1 < len(ctx.text.split("\n")) else ""
        findings.append({
            "id": rule["id"],
            "severity": rule["severity"],
            "title": rule["title"],
            "owasp": rule["owasp"],
            "why": rule["why"],
            "fix": rule["fix"],
            "path": ctx.rel,
            "line": line_no,
            "snippet": _snippet(raw_line or call),
            "kind": "flow",
        })
        if len(findings) >= 2:
            break

    return findings


CUSTOM_DETECTORS = [detect_prompt_concat, detect_retrieval_filter]
