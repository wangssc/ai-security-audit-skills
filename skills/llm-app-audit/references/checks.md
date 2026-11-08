# The 18 checks, and which of them this tool can actually see

This is the underlying checklist. It is deliberately larger than what the
scanner detects, because a report that claims coverage it does not have is
worse than a shorter report.

Read the "seen by" column before trusting an empty result. A check with no rule
and no probe is a check you still have to do yourself.

Column meanings:

- **static** — a rule in `scripts/rules.py` or `scripts/detectors.py` reads it
  off disk. Evidence is a file and a line.
- **probe** — `scripts/probe.py` can test it against a live endpoint, with a
  planted canary. Opt-in, because it sends traffic.
- **manual** — nothing here finds it. Listed so you know the gap is yours.

| # | Check | OWASP | Seen by | What it costs when ignored |
| --- | --- | --- | --- | --- |
| C01 | Direct prompt injection | LLM01 | static `LAI-101`, `LAI-201`; probe `P01` | One user turn replaces your instruction. No exploit chain, no memory corruption. |
| C02 | Indirect injection through a retrieved document | LLM01 | static `LAI-102`, `LAI-108`; probe `P02` | Nobody has to talk to your model. One sentence in one document you will retrieve. |
| C03 | System prompt disclosure | LLM07 | static `LAI-116`, `LAI-111`, `LAI-114`; probe `P03` | Your operating rules, internal hosts, and routing logic become public. |
| C04 | Jailbreak by encoding, role-play, or language switch | LLM01 | static `LAI-201`; probe `P04` | A keyword filter is bypassed by base64. The model still understands it. |
| C05 | Sensitive data echoed back | LLM02 | static `LAI-110`; probe `P05` | A data-loss incident with a timestamp. It is a breach, not a bug. |
| C06 | Cross-tenant retrieval | LLM08 | static `LAI-109`; probe `P06` | Another customer's document is read aloud to this one. |
| C07 | Harmful content generation | LLM05 | static `LAI-110`; probe `P07` | Your product becomes the delivery mechanism. |
| C08 | Confident fabrication of policy, price, or regulation | LLM09 | **probe `P08` only** | The user pastes it into a filing. Liability, not embarrassment. |
| C09 | Executable or destructive output returned verbatim | LLM05 | static `LAI-104`, `LAI-105`; probe `P09` | The model writing it is expected. Shipping it unmodified is the finding. |
| C10 | Agent tool invoked beyond its authority | LLM06 | static `LAI-106`; probe `P10` | "The model said something wrong" becomes "the model dropped the table". |
| C11 | Irreversible action with no approval gate | LLM06 | static `LAI-107`; probe `P10` | The damage is outside your system before anyone reads the transcript. |
| C12 | Credential exposure through tool, plugin, or MCP config | LLM02 | static `LAI-103`, `LAI-111` | A key in a tool definition is a key in a log, a trace, and a screenshot. |
| C13 | Tool return value treated as instruction | LLM01 | static `LAI-108` | A fetched page or an email body becomes an instruction your agent obeys. |
| C14 | Bulk extraction / model distillation | LLM10 | static `LAI-202`, `LAI-118`, `LAI-113` | Billing incident and capability theft in the same channel. |
| C15 | Backdoor trigger words / training data poisoning | LLM04 | **manual** | Nothing static finds this. It needs known-answer probes and dataset lineage. |
| C16 | No conversation audit trail | operational | static `LAI-203` | After an incident you cannot answer what it said or what it read. |
| C17 | Multi-tenant or multi-session isolation failure | LLM08 | static `LAI-109` | One session's context appears in another's answer. |
| C18 | Model version changed without regression | operational | static `LAI-204`, `LAI-113` | Behaviour moves with no diff, and refusal rate moves first. |

Integrity note: C16 and C18 are not in the OWASP LLM Top 10. They are
operational requirements that cause real incidents, and they are labelled as
such rather than dressed up as taxonomy.

## Two checks this tool deliberately does not attempt

**C15, data poisoning.** Detecting a backdoor requires knowing the trigger,
which means having the training data or running a large probe corpus. A static
reader looking at application code cannot see it, and pretending otherwise
would be the single most misleading thing in this package.

**C08, hallucination.** Grounding quality is a property of the model, the
retrieval set, and the prompt together. The probe can catch one confident
fabrication about a specific article number; that is a sample, not a measurement.
