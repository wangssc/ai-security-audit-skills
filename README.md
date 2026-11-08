# AI Security Audit Skills

Three agent skills that read bytes off disk and report what an attacker would use first.
No target is launched, imported, or executed.

Built for [Agent Skills](https://code.claude.com/docs/en/skills) — works in Claude Code, Claude
Desktop, and any assistant that loads `SKILL.md`.

| Skill | Question it answers | Reads |
| --- | --- | --- |
| [`electron-surface-audit`](skills/electron-surface-audit/SKILL.md) | Can a renderer compromise in this desktop app become arbitrary code execution? | `.exe` / `.app` / install dir |
| [`llm-app-audit`](skills/llm-app-audit/SKILL.md) | Does untrusted text reach the instruction string, the tool call, or `eval`? | source repo + prompt files |
| [`invisible-char-audit`](skills/invisible-char-audit/SKILL.md) | Does this text contain characters a human cannot see but a compiler or model will obey? | any file or pasted snippet |

## Why these three

They share one property most security tooling does not: they never run the thing they are
auditing. An audit that executes the target has already given the target control. Each of these
opens files, parses bytes, and writes a report.

Every finding cites a file and a line, or says plainly that the evidence is *the absence of a
control*. A finding you cannot verify is worse than no finding.

## Install

```bash
npx skills add wangssc/ai-security-audit-skills
```

Or copy the directory you want into your skills folder:

```bash
git clone https://github.com/wangssc/ai-security-audit-skills.git
cp -r ai-security-audit-skills/skills/electron-surface-audit ~/.claude/skills/
```

Each skill is self-contained: `SKILL.md`, `scripts/`, `references/`. Python 3.8+, standard
library only, no `pip install`.

## What the output actually looks like

Verbatim from real runs on 2026-11-08. Not illustrations.

**`electron-surface-audit`** on a shipped Electron desktop app:

```
score    23/100   grade F (critical)
         fuse penalty 117, code penalty 15
```

Of nine fuses, eight were at risk: `Run as Node` enabled, `NODE_OPTIONS support` enabled,
`--inspect arguments` enabled, `Embedded ASAR integrity` disabled, `Only load app from ASAR`
disabled, `Browser-specific V8 snapshot` disabled, `file:// extra privileges` enabled,
`Cookie encryption` disabled. Two code findings: `ES-011` — `shell.openExternal` called with a
non-literal argument (high, with the file and line in the bundled renderer); `ES-010` — no
Content-Security-Policy, reported as an explicit absence check rather than a silent pass.

**`invisible-char-audit`** on its own `fixtures/vulnerable/`:

```
score    2/100   grade F
         critical 5  high 6  medium 3  low 0
```

14 findings across nine rules, including U+E0020 (35 tag characters that decode to
`this sentence was invisible to you`), U+0430 (Cyrillic `а` shadowing `a` inside an identifier),
and U+202E (RTL override). Each with file, line, and column. `--clean-out FILE` writes a
character-stripped copy and never overwrites the input.

**`llm-app-audit`** on its `references/examples/vulnerable-rag/`:

```
score    10/100   grade F
         critical 2  high 5  medium 7  low 0
```

Top findings: `LAI-101` — user input spliced into the instruction string at `app.py:42`, mapped
to OWASP LLM01; `LAI-103` — a credential written inline instead of read from the environment at
`app.py:25`, mapped to LLM02.

## What these do not do

- Do not run, import, or open the target. `llm-app-audit`'s probe mode is opt-in and
  requires a live endpoint URL you supply; everything else is static.
- Do not install or modify anything in the audited project.
- Do not promise completeness. They report what the rules cover and say when a control is absent
  rather than assuming it is present.

## Scope

`electron-surface-audit` covers fuses, ASAR integrity, `nodeIntegration`, `contextIsolation`,
`sandbox`, IPC sender validation, `openExternal` guards, updater signing. It does not audit
native modules or binary exploitation.

`llm-app-audit` covers prompt construction, RAG fencing and tenant filtering, tool approval
gates, output sinks (`eval`, raw HTML), and the operational controls around them. It does not
test model behavior beyond the optional canary probe.

`invisible-char-audit` covers bidi controls, Unicode tag blocks, zero-width characters,
Cyrillic/Greek homoglyphs, and space lookalikes. It does not do full confusable-skeleton
matching across the whole Unicode range.

## 中文

三个 Agent Skill，都只读文件、不运行目标程序：审 Electron 桌面应用的攻击面（fuse、ASAR
完整性、IPC 校验）、审 LLM 应用（提示词拼接、RAG 数据围栏、工具调用审批）、查不可见字符
（双向控制符、Unicode tag 块、同形字）。

每条结论都给出文件与行号，或者明确说明"证据是缺少某项防护"。Python 3.10+，仅标准库。

## License

MIT. See each skill's `LICENSE`.
