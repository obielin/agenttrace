"""
agenttrace schema v1.0.0
========================
Structured audit event schema for AI agent decisions.
Designed to satisfy EU AI Act Article 12 (logging obligations),
ISO/IEC 42001, and NIST AI RMF requirements.

This schema is the citable artefact — framework-agnostic, open,
versioned, and hash-chained for tamper evidence.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0.0"
SCHEMA_URL = "https://github.com/obielin/agenttrace/blob/main/SCHEMA.md"


class EventType(str, Enum):
    """Types of auditable agent events."""

    DECISION = "decision"  # Agent makes a choice or plan
    TOOL_CALL = "tool_call"  # Agent invokes a tool or function
    TOOL_RESULT = "tool_result"  # Tool returns a result
    MEMORY_READ = "memory_read"  # Agent reads from memory/context
    MEMORY_WRITE = "memory_write"  # Agent writes to memory
    POLICY_CHECK = "policy_check"  # Policy engine evaluates an action
    HUMAN_REVIEW = "human_review"  # Human oversight event
    ERROR = "error"  # Agent error or exception
    SESSION_START = "session_start"
    SESSION_END = "session_end"


class PolicyDecision(str, Enum):
    """Outcome of a policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    DEFER = "defer"  # Escalated to human review
    UNKNOWN = "unknown"


class RiskTier(str, Enum):
    """EU AI Act risk classification."""

    UNACCEPTABLE = "unacceptable"  # Article 5 — prohibited
    HIGH = "high"  # Annex III — high-risk
    LIMITED = "limited"  # Article 52 — transparency obligations
    MINIMAL = "minimal"  # No specific obligations


@dataclass
class TraceEvent:
    """
    A single auditable event in an agent's decision trace.

    Conforms to agenttrace schema v1.0.0.
    Each event is hash-chained to the previous to detect tampering.

    Fields required by EU AI Act Article 12:
    - event_id, session_id: unique identifiers
    - timestamp_utc: when the event occurred
    - agent_id: which system made the decision
    - event_type: what kind of decision
    - input_hash: cryptographic fingerprint of input
    - policy_decision: what the governance layer decided
    - human_oversight_required: whether human review is needed
    - prev_hash: chain link to previous event (tamper evidence)
    """

    # Identity
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    agent_id: str = "unknown"
    framework: str = ""  # langgraph | openai-agents | claude-code | mcp | custom

    # Timing
    timestamp_utc: float = field(default_factory=time.time)
    duration_ms: float = 0.0

    # Event details
    event_type: EventType = EventType.DECISION
    action: str = ""  # What the agent did / tried to do
    tool_name: str = ""  # Tool invoked (for tool_call events)
    model: str = ""  # LLM model used

    # Data fingerprints (NOT the actual data — privacy preserving)
    input_hash: str = ""  # SHA-256 of input/prompt
    output_hash: str = ""  # SHA-256 of output/response
    context_hash: str = ""  # SHA-256 of context/memory used

    # Governance
    policy_decision: PolicyDecision = PolicyDecision.UNKNOWN
    policy_rules_applied: list[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0-100
    risk_tier: RiskTier = RiskTier.MINIMAL
    human_oversight_required: bool = False
    human_reviewer_id: str = ""

    # Compliance annotations
    eu_ai_act_article: str = ""  # e.g. "Article 12"
    iso_42001_clause: str = ""  # e.g. "Clause 6.1"
    nist_ai_rmf_function: str = ""  # e.g. "GOVERN 1.1"

    # Chain integrity
    prev_hash: str = ""  # Hash of previous event in chain
    event_hash: str = ""  # SHA-256 of this event (computed)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this event for chain integrity."""
        payload = {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type.value,
            "action": self.action,
            "tool_name": self.tool_name,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "policy_decision": self.policy_decision.value,
            "risk_score": self.risk_score,
            "prev_hash": self.prev_hash,
        }
        if self.event_type == EventType.SESSION_END and "event_count" in self.metadata:
            payload["event_count"] = self.metadata["event_count"]
        serialised = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialised.encode("utf-8")).hexdigest()

    def seal(self) -> "TraceEvent":
        """Compute and store the event hash. Call after setting prev_hash."""
        self.event_hash = self.compute_hash()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "schema_url": SCHEMA_URL,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "framework": self.framework,
            "timestamp_utc": self.timestamp_utc,
            "duration_ms": self.duration_ms,
            "event_type": self.event_type.value,
            "action": self.action,
            "tool_name": self.tool_name,
            "model": self.model,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "context_hash": self.context_hash,
            "policy_decision": self.policy_decision.value,
            "policy_rules_applied": self.policy_rules_applied,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier.value,
            "human_oversight_required": self.human_oversight_required,
            "human_reviewer_id": self.human_reviewer_id,
            "eu_ai_act_article": self.eu_ai_act_article,
            "iso_42001_clause": self.iso_42001_clause,
            "nist_ai_rmf_function": self.nist_ai_rmf_function,
            "prev_hash": self.prev_hash,
            "event_hash": self.event_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TraceEvent":
        event = cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            session_id=data.get("session_id", ""),
            agent_id=data.get("agent_id", "unknown"),
            framework=data.get("framework", ""),
            timestamp_utc=data.get("timestamp_utc", time.time()),
            duration_ms=data.get("duration_ms", 0.0),
            event_type=EventType(data.get("event_type", "decision")),
            action=data.get("action", ""),
            tool_name=data.get("tool_name", ""),
            model=data.get("model", ""),
            input_hash=data.get("input_hash", ""),
            output_hash=data.get("output_hash", ""),
            context_hash=data.get("context_hash", ""),
            policy_decision=PolicyDecision(data.get("policy_decision", "unknown")),
            policy_rules_applied=data.get("policy_rules_applied", []),
            risk_score=data.get("risk_score", 0.0),
            risk_tier=RiskTier(data.get("risk_tier", "minimal")),
            human_oversight_required=data.get("human_oversight_required", False),
            human_reviewer_id=data.get("human_reviewer_id", ""),
            eu_ai_act_article=data.get("eu_ai_act_article", ""),
            iso_42001_clause=data.get("iso_42001_clause", ""),
            nist_ai_rmf_function=data.get("nist_ai_rmf_function", ""),
            prev_hash=data.get("prev_hash", ""),
            event_hash=data.get("event_hash", ""),
            metadata=data.get("metadata", {}),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
        )
        return event

    def __repr__(self) -> str:
        return (
            f"TraceEvent({self.event_type.value}, "
            f"agent={self.agent_id!r}, "
            f"decision={self.policy_decision.value}, "
            f"risk={self.risk_score:.0f})"
        )
