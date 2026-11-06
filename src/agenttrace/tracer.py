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


class _ToolTrace:
    """Context object returned by :meth:`AgentTracer.trace_tool`.

    The object yielded by the ``with`` block is a mutable holder, not the
    sealed event itself: the event is only recorded (and hash-chained)
    when the block exits, so values assigned inside the block are part of
    the recorded event instead of breaking its hash. Set either
    ``output_text`` (hashed on exit) or ``output_hash`` directly, as in
    the ``AgentTracer`` class docstring; an explicit ``output_hash`` wins
    if both are set. After the block exits, ``event`` holds the recorded
    :class:`~agenttrace.schema.TraceEvent` (or ``None`` if not exited yet).
    On an exception inside the block an ERROR event is recorded instead
    of a TOOL_CALL event, with only the exception type noted in its
    metadata, and the exception propagates.
    """

    def __init__(
        self,
        tracer: AgentTracer,
        tool: str,
        input_text: str = "",
        model: str = "",
        risk_score: float = 0.0,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self._tracer = tracer
        self.tool = tool
        self.input_text = input_text
        self.model = model
        self.risk_score = risk_score
        self.metadata = metadata
        self._kwargs = kwargs
        self.output_text = ""
        self.output_hash = ""
        self.event: TraceEvent | None = None
        self.duration_ms = 0.0
        self._start = 0.0

    def __enter__(self) -> _ToolTrace:
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type: Any, exc: Any, _tb: Any) -> bool:
        self.duration_ms = (time.monotonic() - self._start) * 1000.0
        metadata = dict(self.metadata) if self.metadata else {}
        if exc_type is not None:
            # A failed tool call is an ERROR event, not a TOOL_CALL:
            # issue #6 asks for "tool_call ... or an error event", and
            # TOOL_CALL is reserved for successful executions. Only the
            # exception type is persisted (CWE-532): the raw message
            # may contain credentials or user data.
            metadata["error"] = exc_type.__name__
            self.event = self._tracer.record(
                EventType.ERROR,
                tool_name=self.tool,
                action=f"tool_call:{self.tool}",
                input_text=self.input_text,
                output_text=self.output_text,
                output_hash=self.output_hash,
                model=self.model,
                risk_score=self.risk_score,
                duration_ms=self.duration_ms,
                metadata=metadata,
                policy_decision=PolicyDecision.DENY,
                **self._kwargs,
            )
            return False
        self.event = self._tracer.record(
            EventType.TOOL_CALL,
            tool_name=self.tool,
            action=f"tool_call:{self.tool}",
            input_text=self.input_text,
            output_text=self.output_text,
            output_hash=self.output_hash,
            model=self.model,
            risk_score=self.risk_score,
            duration_ms=self.duration_ms,
            metadata=metadata,
            **self._kwargs,
        )
        return False


class AgentTracer:
    """Session manager for agent audit events.

    Records each event (decision, tool call, policy check, ...) as a
    :class:`~agenttrace.schema.TraceEvent`, appends it to an in-memory
    list, and chains the event hashes so tampering is detectable. A
    tracer session is a single agent run; the session ends by writing
    a JSONL bundle to ``output_dir`` and can be verified later.

    Typical usage (LangGraph-style tool node)::

        tracer = AgentTracer(agent_id="my-agent", framework="langgraph")
        tracer.start_session()
        with tracer.trace_tool("search", input_text=query) as t:
            result = tools.search(query)
            t.output_text = result  # hashed, not stored raw
        path = tracer.end_session()  # writes the JSONL bundle

    ``trace_tool`` records one event per block exit: TOOL_CALL on
    success, ERROR if the block raises. The returned event is
    available as ``t.event`` after the block.
    """

    def __init__(
        self,
        agent_id: str = "agent",
        framework: str = "custom",
        session_id: str | None = None,
        output_dir: str | pathlib.Path = "traces",
    ) -> None:
        self.agent_id = agent_id
        self.framework = framework
        self.session_id = session_id or str(uuid.uuid4())
        self.output_dir = pathlib.Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[TraceEvent] = []
        self.bundle_path: pathlib.Path | None = None
        self._prev_hash = ""

    def start_session(self) -> TraceEvent:
        """Record a session-start event and return it."""
        return self.record(EventType.SESSION_START, action="session_start")

    def record(
        self,
        event_type: EventType,
        *,
        action: str = "",
        tool_name: str = "",
        input_text: str = "",
        output_text: str = "",
        output_hash: str = "",
        model: str = "",
        risk_score: float = 0.0,
        risk_tier: RiskTier = RiskTier.LOW,
        policy_decision: PolicyDecision = PolicyDecision.ALLOW,
        policy_rules: list[str] | None = None,
        human_oversight_required: bool = False,
        context_text: str = "",
        duration_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> TraceEvent:
        """Record one event, seal it, and append it to the hash chain."""
        event = TraceEvent(
            session_id=self.session_id,
            agent_id=self.agent_id,
            framework=self.framework,
            event_type=event_type,
            action=action,
            tool_name=tool_name,
            input_hash=_hash_text(input_text) if input_text else "",
            output_hash=output_hash or (_hash_text(output_text) if output_text else ""),
            model=model,
            risk_score=risk_score,
            risk_tier=risk_tier,
            policy_decision=policy_decision,
            policy_rules=policy_rules or [],
            human_oversight_required=human_oversight_required,
            context_hash=_hash_text(context_text) if context_text else "",
            duration_ms=duration_ms,
            metadata=metadata or {},
            prev_hash=self._prev_hash,
        )
        event.seal()
        self.events.append(event)
        self._prev_hash = event.event_hash
        return event

    def record_decision(
        self, action: str, risk_score: float = 0.0, **kwargs: Any
    ) -> TraceEvent:
        """Record a decision event."""
        return self.record(
            EventType.DECISION,
            action=action,
            risk_score=risk_score,
            **kwargs,
        )

    def record_tool_call(
        self,
        tool: str,
        input_text: str = "",
        output_text: str = "",
        output_hash: str = "",
        model: str = "",
        risk_score: float = 0.0,
        **kwargs: Any,
    ) -> TraceEvent:
        """Record a tool-call event (hashes, never stores raw text)."""
        return self.record(
            EventType.TOOL_CALL,
            tool_name=tool,
            action=f"tool_call:{tool}",
            input_text=input_text,
            output_text=output_text,
            output_hash=output_hash,
            model=model,
            risk_score=risk_score,
            **kwargs,
        )

    def record_error(self, action: str, metadata: dict[str, Any] | None = None) -> TraceEvent:
        """Record an error event (a failed tool call or agent error)."""
        return self.record(
            EventType.ERROR,
            action=action,
            risk_score=50.0,
            policy_decision=PolicyDecision.DENY,
            metadata=metadata or {},
        )

    def trace_tool(
        self,
        tool: str,
        input_text: str = "",
        model: str = "",
        risk_score: float = 0.0,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> _ToolTrace:
        """Time a tool call and record it as one TOOL_CALL event on exit,
        or one ERROR event if the block raises.

        Args:
            tool: Tool name, e.g. ``"search"``.
            input_text: Tool input; only its hash is persisted.
            model: Model used by the tool, if any.
            risk_score: Risk score for the call.
            metadata: Extra metadata attached to the event.
            **kwargs: Extra fields forwarded to :meth:`record`.

        Inside the block, set ``t.output_text`` (hashed on exit) or
        ``t.output_hash`` directly. After the block, ``t.event`` is the
        recorded event and ``t.duration_ms`` is the elapsed time. This
        does not start or end a session; call ``start_session`` /
        ``end_session`` around it as usual. An exception inside the block
        is recorded as an ERROR event (only the exception type is kept
        in the event's metadata) and then re-raised.
        """
        return _ToolTrace(
            self,
            tool,
            input_text=input_text,
            model=model,
            risk_score=risk_score,
            metadata=metadata,
            **kwargs,
        )

    def end_session(self, flush: bool = True) -> pathlib.Path | None:
        """Record a session-end event and, by default, flush the bundle."""
        self.record(EventType.SESSION_END, action="session_end")
        if not flush:
            return None
        return self.flush()

    def flush(self) -> pathlib.Path:
        """Write all events as JSONL; return the bundle path."""
        timestamp = time.strftime("%Y%m%dT%H%M%S")
        filename = f"{self.session_id}_{timestamp}.jsonl"
        path = self.output_dir / filename
        with path.open("w", encoding="utf-8") as f:
            for event in self.events:
                f.write(json.dumps(event.to_dict()) + "\n")
        self.bundle_path = path
        return path

    def verify(self, path: str | pathlib.Path) -> tuple[bool, list[str]]:
        """Verify a bundle's hash chain and event hashes.

        Returns ``(True, [])`` when valid, otherwise ``(False, errors)``.
        """
        errors: list[str] = []
        prev_hash = ""
        try:
            with pathlib.Path(path).open(encoding="utf-8") as f:
                lines = [line for line in f if line.strip()]
        except OSError as exc:
            return False, [f"cannot read bundle: {exc}"]
        for i, line in enumerate(lines):
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {i + 1}: invalid JSON: {exc}")
                continue
            event = TraceEvent.from_dict(data)
            if event.prev_hash != prev_hash:
                errors.append(
                    f"line {i + 1}: prev_hash mismatch "
                    f"(expected {prev_hash[:8]}, got {event.prev_hash[:8]})"
                )
            if event.compute_hash() != event.event_hash:
                errors.append(f"line {i + 1}: event hash mismatch")
            prev_hash = event.event_hash
        return (not errors), errors


def hash_text(text: str) -> str:
    """SHA-256 hash of a string. Public alias of the internal helper."""
    return _hash_text(text)
