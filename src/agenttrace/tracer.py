"""
AgentTracer — session manager, JSONL writer, and bundle verifier.
Zero external dependencies.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import time
import uuid
from typing import Any

from agenttrace.schema import (
    EventType,
    PolicyDecision,
    RiskTier,
    TraceEvent,
)


def _hash_text(text: str) -> str:
    """SHA-256 hash of a string. Used for input/output fingerprinting."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AgentTracer:
    """
    Records tamper-evident, hash-chained audit trails for AI agent decisions.

    Conforms to agenttrace schema v1.0.0.
    Output is newline-delimited JSON (JSONL) — one event per line.

    Example (standalone):
        tracer = AgentTracer(agent_id="my-research-agent", framework="custom")
        tracer.start_session()
        tracer.record_tool_call(tool="web_search", input_text="AI governance 2026")
        tracer.record_decision(action="summarise results", policy_decision="allow")
        tracer.end_session()
        print(tracer.bundle_path)

    Example (LangGraph):
        tracer = AgentTracer(agent_id="langgraph-agent", framework="langgraph")
        tracer.start_session(metadata={"graph": "research_graph"})

        # In your node functions:
        with tracer.trace_tool("search", input_text=query) as t:
            result = search_tool(query)
            t.output_hash = agenttrace.hash_text(result)

    Example (OpenAI Agents SDK):
        tracer = AgentTracer(agent_id="openai-agent", framework="openai-agents")
        tracer.start_session()
        tracer.record(EventType.TOOL_CALL, tool_name="code_interpreter",
                      input_text=code, model="gpt-4o")
    """

    def __init__(
        self,
        agent_id: str = "agent",
        framework: str = "custom",
        output_dir: str | pathlib.Path = ".",
        session_id: str | None = None,
        auto_compliance: bool = True,
    ) -> None:
        """
        Args:
            agent_id:        Unique identifier for this agent
            framework:       Framework name (langgraph | openai-agents | claude-code | mcp | custom)
            output_dir:      Directory to write JSONL bundles
            session_id:      Override session ID (auto-generated if None)
            auto_compliance: Auto-annotate EU AI Act / ISO 42001 / NIST fields
        """
        self.agent_id = agent_id
        self.framework = framework
        self.output_dir = pathlib.Path(output_dir)
        self.session_id = session_id or str(uuid.uuid4())
        self.auto_compliance = auto_compliance

        self._events: list[TraceEvent] = []
        self._prev_hash = ""
        self._session_active = False
        self._bundle_path: pathlib.Path | None = None

    @property
    def bundle_path(self) -> pathlib.Path | None:
        return self._bundle_path

    @property
    def events(self) -> list[TraceEvent]:
        return list(self._events)

    @property
    def event_count(self) -> int:
        return len(self._events)

    def start_session(self, metadata: dict[str, Any] | None = None) -> TraceEvent:
        """Begin a new audit session."""
        self._session_active = True
        event = self.record(
            EventType.SESSION_START,
            action="session_started",
            metadata=metadata or {},
        )
        return event

    def end_session(
        self,
        flush: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> pathlib.Path | None:
        """End the session, optionally writing the JSONL bundle."""
        self.record(
            EventType.SESSION_END,
            action="session_ended",
            metadata={**(metadata or {}), "event_count": len(self._events) + 1},
        )
        self._session_active = False
        if flush:
            return self.flush()
        return None

    def record(
        self,
        event_type: EventType = EventType.DECISION,
        action: str = "",
        tool_name: str = "",
        model: str = "",
        input_text: str = "",
        output_text: str = "",
        context_text: str = "",
        policy_decision: PolicyDecision = PolicyDecision.ALLOW,
        policy_rules: list[str] | None = None,
        risk_score: float = 0.0,
        risk_tier: RiskTier = RiskTier.MINIMAL,
        human_oversight_required: bool = False,
        duration_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> TraceEvent:
        """Record a single audit event."""
        event = TraceEvent(
            session_id=self.session_id,
            agent_id=self.agent_id,
            framework=self.framework,
            timestamp_utc=time.time(),
            duration_ms=duration_ms,
            event_type=event_type,
            action=action,
            tool_name=tool_name,
            model=model,
            input_hash=_hash_text(input_text) if input_text else "",
            output_hash=_hash_text(output_text) if output_text else "",
            context_hash=_hash_text(context_text) if context_text else "",
            policy_decision=policy_decision,
            policy_rules_applied=policy_rules or [],
            risk_score=risk_score,
            risk_tier=risk_tier,
            human_oversight_required=human_oversight_required,
            prev_hash=self._prev_hash,
            metadata=metadata or {},
        )

        if self.auto_compliance:
            _annotate_compliance(event)

        event.seal()
        self._prev_hash = event.event_hash
        self._events.append(event)
        return event

    def record_tool_call(
        self,
        tool: str,
        input_text: str = "",
        model: str = "",
        risk_score: float = 0.0,
        **kwargs: Any,
    ) -> TraceEvent:
        """Shortcut for recording a tool invocation."""
        return self.record(
            EventType.TOOL_CALL,
            tool_name=tool,
            action=f"tool_call:{tool}",
            input_text=input_text,
            model=model,
            risk_score=risk_score,
            **kwargs,
        )

    def record_decision(
        self,
        action: str,
        policy_decision: PolicyDecision = PolicyDecision.ALLOW,
        risk_score: float = 0.0,
        **kwargs: Any,
    ) -> TraceEvent:
        """Shortcut for recording an agent decision."""
        return self.record(
            EventType.DECISION,
            action=action,
            policy_decision=policy_decision,
            risk_score=risk_score,
            **kwargs,
        )

    def record_error(self, action: str, metadata: dict[str, Any] | None = None) -> TraceEvent:
        """Record an agent error event."""
        return self.record(
            EventType.ERROR,
            action=action,
            policy_decision=PolicyDecision.DENY,
            risk_score=50.0,
            metadata=metadata or {},
        )

    def flush(self) -> pathlib.Path:
        """Write all events to a JSONL bundle file."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"agenttrace_{self.session_id[:8]}_{int(time.time())}.jsonl"
        path = self.output_dir / filename
        with path.open("w", encoding="utf-8") as f:
            for event in self._events:
                f.write(json.dumps(event.to_dict()) + "\n")
        self._bundle_path = path
        return path

    def verify(self, path: pathlib.Path | None = None) -> tuple[bool, list[str]]:
        """
        Verify the hash chain integrity of a JSONL bundle.

        Returns:
            (is_valid, list_of_errors)
        """
        target = path or self._bundle_path
        if target is None:
            return False, ["No bundle path — call flush() first"]

        if not target.exists():
            return False, [f"Bundle not found: {target}"]

        errors = []
        prev_hash = ""
        events = []

        with target.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = TraceEvent.from_dict(data)
                    events.append(event)
                except Exception as e:
                    errors.append(f"Line {i+1}: parse error — {e}")
                    continue

        if not events:
            return False, errors + ["Bundle is empty"]
        if events[0].event_type != EventType.SESSION_START:
            errors.append("Bundle must begin with session_start")
        if events[-1].event_type != EventType.SESSION_END:
            errors.append("Bundle must end with session_end")
        elif events[-1].metadata.get("event_count") != len(events):
            errors.append("Session event_count does not match the bundle length")

        for i, event in enumerate(events):
            # Check prev_hash chain
            if event.prev_hash != prev_hash:
                errors.append(
                    f"Event {i+1} ({event.event_id[:8]}): " f"prev_hash mismatch — chain broken"
                )

            # Recompute and verify event_hash
            stored_hash = event.event_hash
            event.event_hash = ""
            recomputed = event.compute_hash()
            if stored_hash != recomputed:
                errors.append(
                    f"Event {i+1} ({event.event_id[:8]}): "
                    f"event_hash mismatch — content may have been tampered"
                )
            event.event_hash = stored_hash
            prev_hash = stored_hash

        return len(errors) == 0, errors


def _annotate_compliance(event: TraceEvent) -> None:
    """Auto-annotate EU AI Act, ISO 42001, NIST AI RMF fields."""
    # EU AI Act Article 12 — Logging obligations for high-risk AI
    if event.event_type in (EventType.DECISION, EventType.TOOL_CALL, EventType.POLICY_CHECK):
        event.eu_ai_act_article = "Article 12"

    # EU AI Act Article 14 — Human oversight
    if event.human_oversight_required or event.event_type == EventType.HUMAN_REVIEW:
        event.eu_ai_act_article = "Article 14"

    # ISO 42001 Clause 6.1 — Actions to address AI risks
    if event.risk_score > 30:
        event.iso_42001_clause = "Clause 6.1"
    elif event.event_type == EventType.POLICY_CHECK:
        event.iso_42001_clause = "Clause 8.4"

    # NIST AI RMF
    if event.event_type == EventType.DECISION:
        event.nist_ai_rmf_function = "GOVERN 1.1"
    elif event.event_type in (EventType.TOOL_CALL, EventType.TOOL_RESULT):
        event.nist_ai_rmf_function = "MANAGE 2.2"
    elif event.event_type == EventType.POLICY_CHECK:
        event.nist_ai_rmf_function = "GOVERN 6.1"


def hash_text(text: str) -> str:
    """Hash text for use as input_hash / output_hash in TraceEvent."""
    return _hash_text(text)
