# agenttrace Schema v1.0.0

**A structured audit event schema for AI agent decisions.**
**Designed for EU AI Act Article 12, ISO/IEC 42001, and NIST AI RMF compliance.**

---

## Overview

The agenttrace schema defines a standardised format for recording AI agent decisions as tamper-evident, hash-chained audit events. Each event is a JSON object written to a newline-delimited JSONL file.

The schema is framework-agnostic. It is designed to be implemented by any AI agent system — LangGraph, OpenAI Agents SDK, Claude Code, MCP, or custom frameworks.

---

## Event fields

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | string | Yes | Schema version (currently `"1.0.0"`) |
| `schema_url` | string | Yes | URL to this schema document |
| `event_id` | UUID string | Yes | Unique identifier for this event |
| `session_id` | UUID string | Yes | Groups events within one agent session |
| `agent_id` | string | Yes | Identifies the AI system that generated the event |
| `framework` | string | No | Agent framework (`langgraph`, `openai-agents`, `claude-code`, `mcp`, `custom`) |
| `timestamp_utc` | float | Yes | Unix timestamp in UTC |
| `duration_ms` | float | No | Duration of the operation in milliseconds |
| `event_type` | enum | Yes | Type of event (see Event Types) |
| `action` | string | No | Human-readable description of the action taken |
| `tool_name` | string | No | Name of the tool invoked (for tool_call events) |
| `model` | string | No | LLM model used to generate the decision |
| `input_hash` | SHA-256 | No | Hash of the input/prompt (not the raw content) |
| `output_hash` | SHA-256 | No | Hash of the output/response |
| `context_hash` | SHA-256 | No | Hash of the context/memory used |
| `policy_decision` | enum | Yes | Policy engine decision (see Policy Decisions) |
| `policy_rules_applied` | list[string] | No | Rule IDs applied by the policy engine |
| `risk_score` | float (0-100) | No | Risk score for this event |
| `risk_tier` | enum | No | EU AI Act risk tier (see Risk Tiers) |
| `human_oversight_required` | boolean | No | Whether this event required human review |
| `human_reviewer_id` | string | No | ID of the human reviewer (if applicable) |
| `eu_ai_act_article` | string | No | Applicable EU AI Act article |
| `iso_42001_clause` | string | No | Applicable ISO 42001 clause |
| `nist_ai_rmf_function` | string | No | Applicable NIST AI RMF function |
| `prev_hash` | SHA-256 | Yes | Hash of the previous event (chain link; empty string for first event) |
| `event_hash` | SHA-256 | Yes | SHA-256 hash of this event's content |
| `metadata` | object | No | Framework-specific metadata |

---

## Event types

| Value | Description |
|---|---|
| `decision` | Agent makes a choice, plan, or reasoned action |
| `tool_call` | Agent invokes a tool or external function |
| `tool_result` | Tool returns a result to the agent |
| `memory_read` | Agent reads from memory or context |
| `memory_write` | Agent writes to memory |
| `policy_check` | Policy engine evaluates an action |
| `human_review` | Human oversight event |
| `error` | Agent error or exception |
| `session_start` | Beginning of an agent session |
| `session_end` | End of an agent session |

---

## Policy decisions

| Value | Description |
|---|---|
| `allow` | Action permitted by policy |
| `deny` | Action blocked by policy |
| `warn` | Action permitted with warning |
| `defer` | Escalated to human review |
| `unknown` | Policy not evaluated |

---

## Risk tiers (EU AI Act)

| Value | Description |
|---|---|
| `unacceptable` | Article 5 — prohibited practices |
| `high` | Annex III — high-risk systems |
| `limited` | Article 52 — transparency obligations |
| `minimal` | No specific obligations |

---

## Hash chain integrity

Each event references the hash of the previous event via `prev_hash`. The first event in a session has `prev_hash = ""`.

The `event_hash` field is computed as SHA-256 of the following fields serialised as JSON (keys sorted alphabetically):

```json
{
  "action": "...",
  "agent_id": "...",
  "event_id": "...",
  "event_type": "...",
  "input_hash": "...",
  "output_hash": "...",
  "policy_decision": "...",
  "prev_hash": "...",
  "risk_score": 0.0,
  "session_id": "...",
  "timestamp_utc": 0.0,
  "tool_name": "..."
}
```

To verify a bundle: recompute each `event_hash` and verify that `prev_hash` matches the `event_hash` of the preceding event.

---

## Privacy design

agenttrace stores **hashes** of inputs and outputs, not the raw content. This satisfies audit requirements (evidence that specific content was processed) while protecting user privacy and reducing retention risk.

Raw content should be stored separately under appropriate data protection controls, with retention periods matching your regulatory obligations.

---

## Compliance mapping

| Schema field | EU AI Act | ISO 42001 | NIST AI RMF |
|---|---|---|---|
| `event_id`, `session_id` | Art. 12 (logging) | Cl. 8.4 | GOVERN 6.1 |
| `timestamp_utc` | Art. 12 (logging) | Cl. 9.1 | MEASURE 2.5 |
| `agent_id`, `framework` | Art. 13 (transparency) | Cl. 5.2 | GOVERN 1.1 |
| `policy_decision` | Art. 9 (risk mgmt) | Cl. 6.1 | MANAGE 2.2 |
| `human_oversight_required` | Art. 14 (oversight) | Cl. 8.5 | GOVERN 5.1 |
| `risk_score`, `risk_tier` | Art. 9 (risk mgmt) | Cl. 6.1 | MAP 1.5 |
| `prev_hash`, `event_hash` | Art. 12 (tamper evidence) | Cl. 8.4 | GOVERN 6.1 |

---

## Example event

```json
{
  "schema_version": "1.0.0",
  "schema_url": "https://github.com/obielin/agenttrace/blob/main/SCHEMA.md",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "agent_id": "research-agent-v2",
  "framework": "langgraph",
  "timestamp_utc": 1714000000.123,
  "duration_ms": 342.5,
  "event_type": "tool_call",
  "action": "tool_call:web_search",
  "tool_name": "web_search",
  "model": "claude-sonnet-4-6",
  "input_hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "output_hash": "",
  "context_hash": "",
  "policy_decision": "allow",
  "policy_rules_applied": [],
  "risk_score": 5.0,
  "risk_tier": "minimal",
  "human_oversight_required": false,
  "human_reviewer_id": "",
  "eu_ai_act_article": "Article 12",
  "iso_42001_clause": "",
  "nist_ai_rmf_function": "MANAGE 2.2",
  "prev_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "event_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "metadata": {"query": "AI governance frameworks 2026"},
  "schema_version": "1.0.0"
}
```

---

## Citation

If you use this schema in research or build on it, please cite:

```
Oraegbunam, L. (2026). agenttrace: Structured audit event schema for AI agent governance.
GitHub. https://github.com/obielin/agenttrace
```

---

*Schema maintained by Linda Oraegbunam.*
*Research focus: Agentic AI Governance.*

## Complete sessions

A verified bundle starts with `session_start` and ends with `session_end`. The
final event includes `metadata.event_count`, counting every event including itself;
this count is covered by its hash. Empty and incomplete bundles fail verification.
Older bundles without the final count also fail this completeness check. This detects
truncation, but an unkeyed hash chain does not authenticate a bundle against a writer
who can rewrite all its events and hashes.
