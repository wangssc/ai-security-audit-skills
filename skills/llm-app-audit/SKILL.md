---
name: llm-app-audit
description: Audit an LLM application for the defects that turn a prompt into control — untrusted text spliced into the instruction string, retrieved documents with no data fence, vector search with no tenant filter, dangerous tools with no approval gate, model output reaching eval or raw HTML, and the operational controls around all of it. Reads source and prompt files off disk and reports file-and-line evidence, never launching the target. Optional opt-in probe mode tests a live endpoint using a planted canary. Use when asked to review, harden, triage, red-team, or pre-launch-check a chatbot, RAG pipeline, agent, or any application with a system prompt.
license: MIT
---

# LLM app audit

An LLM application has two attack surfaces that never appear in a vulnerability
scanner: the text you concatenate into the instruction, and the tools you
hand to whatever reads that instruction. This skill reads both off disk and
reports what an attacker would use first.

No model is called. No target code is imported or executed. Every finding cites
a file and a line, or says plainly that the evidence is the absence of a control.

## When to use it

- "Is this chatbot safe to ship?" — you have a repo and need an answer with evidence.
- A RAG pipeline is about to go live and nobody has looked at how the retrieved
  chunks reach the prompt.
- An agent has tool access and no one has asked which of those tools can send,
  delete, or pay.
- A vendor's assistant needs a posture check before you connect it to anything.

## Run it

```bash
python scripts/audit.py ./my-llm-app
python scripts/audit.py ./my-llm-app --json
python scripts/audit.py ./my-llm-app --markdown report.md
```

Point it at the project directory. It reads `.py`, `.js`, `.ts`, `.md`,
`.yaml`, `.json`, `.toml` and prompt files, skips `node_modules`, `.git`,
`dist`, and virtualenvs, and stops at 4000 files.

`--fail-on critical|high|medium|low|none` sets the exit code gate (default
`high`). Exit codes: `0` nothing at or above the threshold, `1` findings,
`2` target unreadable, `3` probe mode could not run.

### Live probe mode — read this before using it

```bash
python scripts/audit.py ./my-llm-app \
  --probe \
  --endpoint https://api.example.com/v1/chat/completions \
  --model gpt-4o-2024-11-20 \
  --api-key "$OPENAI_API_KEY" \
  --canary CANARY-8F21XQ
```

This is the only part that sends traffic, and it sends prompts designed to
break the target. It will look like an attack in that endpoint's logs, because
it is one. Run it against your own system, or one you have written permission to
test. There is no setting that makes this safe to point at somebody else.

**The canary is not optional, and that is the point.** You cannot detect a
leaked system prompt without a string you know is inside it. Plant an unusual
token in the target's system prompt first, then pass it here. Without one, the
results cannot be graded and the tool refuses to invent a verdict.

`--dry-run` prints all ten payloads without sending anything — use it to read
what the probe set actually does before you run it.

## What it looks at

**Instruction construction (`LAI-101`, `LAI-102`).** Whether user text and
retrieved text reach the instruction as *content* or as *structure*. The check
is relational: the danger is not an f-string, it is that a specific untrusted
name reached a string used as an instruction. These use a small lexer and brace
extraction rather than a line regex, because a regex for `{...}` flags every log
line in the codebase.

```python
prompt = f"{SYSTEM}\n{context}\nUser asked: {user_input}"   # LAI-101, LAI-102
```
```python
messages = [
    {"role": "system", "content": INSTRUCTION},
    {"role": "user", "content": fence(docs)},
    {"role": "user", "content": user_input},               # separate turn
]
```

**Retrieval isolation (`LAI-109`).** Whether the vector search narrows
candidates by caller identity *inside the query*. A filter applied after
ranking, or a sentence in the prompt asking the model to be careful, is not
isolation — it is a request.

**Tool exposure (`LAI-106`, `LAI-107`, `LAI-108`).** Whether the model holds a
general shell, SQL handle, or file writer, and whether the irreversible ones
stage an action for approval rather than firing inside the loop.

**Output handling (`LAI-104`, `LAI-105`, `LAI-110`).** Whether model text
reaches `eval`, `exec`, `innerHTML`, or the user with no moderation pass.

**Operational controls (`LAI-117`, `LAI-118`, `LAI-201` to `LAI-204`).**
Timeouts, input caps, rate limits, injection detection, audit trail, and whether
a tagged eval set exists to catch the next model swap.

**Credentials and configuration (`LAI-103`, `LAI-111` to `LAI-116`).** Keys in
source, prompts in logs, wildcard CORS, debug flags, floating model aliases,
uploaded files read without a size or type guard.

`references/checks.md` maps all of this onto an 18-item checklist with the
OWASP LLM Top 10 reference for each, **including the two items nothing here can
see**. Read that column before you treat an empty report as a clean one.

## Reading the result

`score 0–100` with a letter grade, computed from severity-weighted penalties on
an exponential curve, capped at 60 while any critical finding stands. A small
codebase with one live injection path is not "mostly fine".

`not assessed` is a real outcome, and it is not 100. If no model call was found
in the tree, either the target is not an LLM application or the call is behind a
wrapper the scanner does not recognise. A launcher and a vulnerable app must not
print the same number.

Every finding carries four parts: where, why, fix, and the OWASP item it maps
to. The `why` is written as the attack, not as a rule description, because the
person who has to prioritise it needs to know what happens if they do not.

## What it cannot do

- **It does not run the target.** It cannot see which instruction the model
  actually received, whether a guard fired, or what a retrieved document
  contained at runtime.
- **It does not do data flow across functions.** `openExternal(x)` where `x` was
  validated three call frames away will still be reported. Treat `LAI-101` and
  `LAI-102` hits as "needs a human read", not as proof of exploitability.
- **It cannot see C15 (data poisoning) or grade C08 (hallucination).** Say so in
  the report rather than implying coverage.
- **The probe set is ten payloads, not a fuzzer.** Ten is enough to tell whether
  a guard exists; it is not enough to conclude one is strong.
- **It does not judge your architecture.** Whether the agent *should* have tool
  access is a design question. This tool assumes the access is intended and asks
  whether the boundary is enforced in code.

## What to avoid

- **Do not report the score to a stakeholder.** Report the findings and their
  locations. A number invites "can we get to 90 by Friday", and the answer is
  usually deleting a rule's trigger rather than fixing the defect.
- **Do not treat a clean scan as a security sign-off.** `not assessed` and
  "no pattern matched" are different claims, and neither is an audit opinion.
- **Do not run probe mode against a third party** without written authorisation.
  It is indistinguishable from an attack on their side.
- **Do not fix code before configuration.** Fuses before code in the Electron
  analogue; here it is retrieval filter and tool boundary before prompt wording.
  A better-worded prompt does not stop a cross-tenant chunk.

## Files

- `scripts/audit.py` — CLI, exit codes, mode selection
- `scripts/scan.py` — walker, comment stripper, rule application
- `scripts/rules.py` — the rule table: pattern, severity, why, fix, OWASP
- `scripts/detectors.py` — the two relational detectors a line regex cannot do
- `scripts/report.py` — scoring and text/Markdown/JSON rendering
- `scripts/probe.py` — opt-in live probe set and the judge that grades it
- `data/probes.json` — ten payloads with judging rules, bilingual
- `references/checks.md` — 18-item checklist and honest coverage matrix
- `references/examples/vulnerable-rag/` — a deliberately broken sample
- `references/examples/hardened-rag/` — the same app fixed; scores 100
