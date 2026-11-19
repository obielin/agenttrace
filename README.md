# agenttrace

**Audit trails for AI agents, built to support EU AI Act Article 12 record-keeping. Hash-chained, tamper-evident decision logs for LangGraph, OpenAI Agents SDK, Claude Code, and MCP. Zero dependencies.**

[![Tests](https://img.shields.io/badge/Tests-41%20passing-brightgreen?style=flat-square)](tests/)
[![Dependencies](https://img.shields.io/badge/Dependencies-zero-brightgreen?style=flat-square)](pyproject.toml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Schema](https://img.shields.io/badge/Schema-v1.0.0-purple?style=flat-square)](SCHEMA.md)
[![LinkedIn](https://img.shields.io/badge/-Linda_Oraegbunam-blue?logo=linkedin&style=flat-square)](https://www.linkedin.com/in/linda-oraegbunam/)

---

## The problem

The **EU AI Act Article 12** requires high-risk AI systems to maintain logs sufficient to ensure traceability of decisions. The **Colorado AI Act** (June 2026) and **ISO/IEC 42001** have equivalent requirements.

But when you ask most AI agent teams how they'd produce audit evidence for a regulator, the honest answer is: **they can't**. Agent decisions happen inside LLM calls with no structured record of what was decided, why, or with what input.

agenttrace fixes this.

---

## What it does

agenttrace wraps your agent code and emits **tamper-evident, hash-chained JSONL audit bundles** — one event per decision, tool call, or policy check. Each event is:

- **Hash-chained** — SHA-256 linked to the previous event, so any tampering is detectable
- **Privacy-preserving** — stores hashes of inputs/outputs, not the raw content
- **Compliance-annotated** — automatically maps events to EU AI Act articles, ISO 42001 clauses, and NIST AI RMF functions
- **Framework-agnostic** — works with LangGraph, OpenAI Agents SDK, Claude Code, MCP, or any custom agent

---

## Install

```bash
pip install git+https://github.com/obielin/agenttrace.git
```

agenttrace is not on PyPI yet. The PyPI name agenttrace belongs to a different project.

Zero dependencies. Pure Python 3.10+.

---

## Quick start

```python
from agenttrace import AgentTracer

tracer = AgentTracer(agent_id="my-research-agent", framework="langgraph")
tracer.start_session()

# Record what your agent does
tracer.record_tool_call(tool="web_search", input_text="AI governance 2026")
tracer.record_decision(action="summarise findings", policy_decision="allow")
tracer.record_tool_call(tool="write_file", input_text="output.md", risk_score=15.0)

# End session — writes tamper-evident JSONL bundle
path = tracer.end_session()
print(f"Bundle: {path}")  # agenttrace_abc12345_1714000000.jsonl
```

---

## CLI

```bash
# Verify hash chain integrity
agenttrace verify bundle.jsonl

# Generate compliance report
agenttrace report bundle.jsonl

# Export report as JSON
agenttrace report bundle.jsonl --format json
agenttrace export bundle.jsonl --out report.json
```

**Verify output:**
```
  VALID — hash chain intact: agenttrace_abc12345_1714000000.jsonl
```

**Report output:**
```
======================================================================
  AGENTTRACE COMPLIANCE REPORT
  agenttrace schema v1.0.0
======================================================================
  Bundle:      agenttrace_abc12345_1714000000.jsonl
  Agent:       my-research-agent
  Framework:   langgraph

  EVENT SUMMARY
  Total events:          6
  Decisions:             2
  Tool calls:            3
  Errors:                0

  RISK SUMMARY
  Average risk score:    8.3/100
  Maximum risk score:    15.0/100
  DENY decisions:        0

  CHAIN INTEGRITY
  Valid:                 YES

  EU AI ACT COVERAGE
  Article 12 — Logging           SATISFIED — all decisions logged
  Article 12 — Tamper evidence   SATISFIED — SHA-256 hash chain verified
  Article 13 — Transparency      SATISFIED — agent_id and model populated
  Article 14 — Human oversight   SATISFIED — human_oversight_required tracked

  ISO/IEC 42001 COVERAGE
  Clause 6.1 — Risk actions      SATISFIED
  Clause 9.1 — Monitoring        SATISFIED

  NIST AI RMF COVERAGE
  GOVERN 1.1 — Policies          SATISFIED — policy_rules_applied recorded
  MANAGE 2.2 — Incidents         SATISFIED — 0 DENY decisions logged
======================================================================
```

---

## Framework integrations

### LangGraph

```python
from agenttrace import AgentTracer, EventType

tracer = AgentTracer(agent_id="langgraph-agent", framework="langgraph")
tracer.start_session()

def search_node(state):
    tracer.record_tool_call(
        tool="web_search",
        input_text=state["query"],
        model="claude-sonnet-4-6",
    )
    result = search(state["query"])
    tracer.record(EventType.TOOL_RESULT, action="search_complete")
    return {"results": result}
```

### OpenAI Agents SDK

```python
from agenttrace import AgentTracer

tracer = AgentTracer(agent_id="openai-agent", framework="openai-agents")
tracer.start_session()

# Wrap your agent runner
def on_tool_call(tool_name, args):
    tracer.record_tool_call(tool=tool_name, input_text=str(args))

def on_decision(action):
    tracer.record_decision(action=action, policy_decision="allow")
```

### Claude Code hooks

```python
from agenttrace import AgentTracer

tracer = AgentTracer(agent_id="claude-code", framework="claude-code")
tracer.start_session()

# In your PreToolUse hook
tracer.record_tool_call(tool=tool_name, input_text=str(tool_input))

# End of session
tracer.end_session()
```

### Standalone / custom

```python
from agenttrace import AgentTracer, EventType, PolicyDecision

tracer = AgentTracer(agent_id="my-agent")
tracer.start_session()

tracer.record(
    EventType.POLICY_CHECK,
    action="check_payment_access",
    policy_decision=PolicyDecision.DENY,
    risk_score=80.0,
    human_oversight_required=True,
    policy_rules=["rule:no-payment-without-human-approval"],
)

tracer.end_session()
```

---

## Schema

Every event in a bundle conforms to **agenttrace schema v1.0.0**. Key fields:

| Field | Type | Description | Regulation |
|---|---|---|---|
| `event_id` | UUID | Unique event identifier | EU AI Act Art. 12 |
| `session_id` | UUID | Groups events in a session | EU AI Act Art. 12 |
| `agent_id` | string | Identifies the AI system | EU AI Act Art. 13 |
| `timestamp_utc` | float | Unix timestamp (UTC) | EU AI Act Art. 12 |
| `event_type` | enum | decision/tool_call/error/... | EU AI Act Art. 12 |
| `input_hash` | SHA-256 | Hash of input (not raw content) | ISO 42001 |
| `policy_decision` | enum | allow/deny/warn/defer | NIST AI RMF |
| `risk_score` | 0-100 | Event risk score | ISO 42001 Cl. 6.1 |
| `human_oversight_required` | bool | Whether human review needed | EU AI Act Art. 14 |
| `eu_ai_act_article` | string | Auto-annotated article reference | EU AI Act |
| `prev_hash` | SHA-256 | Previous event hash (chain link) | Tamper evidence |
| `event_hash` | SHA-256 | This event's hash | Tamper evidence |

Full schema: [SCHEMA.md](SCHEMA.md)

---

## Verify integrity

```python
from agenttrace import AgentTracer

tracer = AgentTracer(agent_id="agent")
# ... record events ...
path = tracer.flush()

valid, errors = tracer.verify(path)
if not valid:
    print("TAMPERING DETECTED:")
    for err in errors:
        print(f"  {err}")
```

---

## Generate compliance report

```python
from agenttrace import generate_report

report = generate_report("bundle.jsonl")
print(report.to_text())      # Human-readable
print(report.to_dict())      # Machine-readable JSON
```

---

## Standards referenced

- EU AI Act (Regulation (EU) 2024/1689), Articles 12, 13, 14
- ISO/IEC 42001:2023 AI Management Systems
- NIST AI Risk Management Framework 1.0
- OWASP Agentic AI Top 10 (2026)

The schema is designed as a citable artefact for the research community. If you build on this schema, please cite the GitHub repository.

---

**Linda Oraegbunam** | [LinkedIn](https://www.linkedin.com/in/linda-oraegbunam/) | [Twitter](https://twitter.com/Obie_Linda) | [GitHub](https://github.com/obielin)

Repeated `tracer.flush()` calls append only new events to one session bundle.
`end_session()` finishes that same file, and `tracer.bundle_path` stays stable.
