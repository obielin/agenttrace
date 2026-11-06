"""Tests for agenttrace. Run: pytest tests/ -v"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agenttrace import (
    SCHEMA_VERSION,
    AgentTracer,
    ComplianceReport,
    EventType,
    PolicyDecision,
    RiskTier,
    TraceEvent,
    generate_report,
    hash_text,
)

# ── TraceEvent tests ───────────────────────────────

class TestTraceEvent:
    def test_default_creation(self):
        event = TraceEvent()
        assert event.event_id
        assert event.schema_version == SCHEMA_VERSION

    def test_compute_hash_is_deterministic(self):
        event = TraceEvent(agent_id="test", action="search")
        h1 = event.compute_hash()
        h2 = event.compute_hash()
        assert h1 == h2

    def test_seal_sets_event_hash(self):
        event = TraceEvent(agent_id="test")
        assert event.event_hash == ""
        event.seal()
        assert len(event.event_hash) == 64

    def test_hash_changes_with_content(self):
        e1 = TraceEvent(agent_id="agent1", action="search")
        e2 = TraceEvent(agent_id="agent2", action="search")
        assert e1.compute_hash() != e2.compute_hash()

    def test_to_dict_has_all_fields(self):
        event = TraceEvent(agent_id="test", event_type=EventType.TOOL_CALL)
        d = event.to_dict()
        assert "event_id" in d
        assert "session_id" in d
        assert "agent_id" in d
        assert "timestamp_utc" in d
        assert "event_type" in d
        assert "input_hash" in d
        assert "policy_decision" in d
        assert "prev_hash" in d
        assert "event_hash" in d
        assert "eu_ai_act_article" in d
        assert "schema_version" in d

    def test_from_dict_roundtrip(self):
        event = TraceEvent(
            agent_id="test",
            event_type=EventType.TOOL_CALL,
            action="search",
            tool_name="search",
        )
        event.seal()
        d = event.to_dict()
        restored = TraceEvent.from_dict(d)
        assert restored.agent_id == "test"
        assert restored.action == "search"
        assert restored.event_type == EventType.TOOL_CALL
        assert restored.event_hash == event.event_hash

    def test_from_dict_with_string_enums(self):
        event = TraceEvent(
            event_type=EventType.TOOL_CALL,
            risk_tier=RiskTier.HIGH,
            policy_decision=PolicyDecision.DENY,
        )
        d = event.to_dict()
        restored = TraceEvent.from_dict(d)
        assert restored.event_type == EventType.TOOL_CALL
        assert restored.risk_tier == RiskTier.HIGH
        assert restored.policy_decision == PolicyDecision.DENY

    def test_to_dict_serializable(self):
        event = TraceEvent(agent_id="test", action="search")
        event.seal()
        text = json.dumps(event.to_dict())
        assert "test" in text

    def test_from_dict_missing_keys_use_defaults(self):
        event = TraceEvent.from_dict({})
        assert event.agent_id == "agent"
        assert event.event_type == EventType.DECISION
        assert event.risk_tier == RiskTier.LOW
        assert event.policy_decision == PolicyDecision.ALLOW

    def test_from_dict_coerces_string_timestamps(self):
        event = TraceEvent.from_dict({"timestamp_utc": 1234567890})
        assert event.timestamp_utc == "1234567890"

    def test_event_with_invalid_enum_falls_back(self):
        event = TraceEvent.from_dict({"event_type": "not_a_real_type"})
        assert event.event_type == EventType.DECISION

    def test_repr_is_informative(self):
        event = TraceEvent(agent_id="test", action="search")
        assert "search" in repr(event)


# ── AgentTracer tests ──────────────────────────────

class TestAgentTracer:
    @pytest.fixture
    def tracer(self, tmp_path):
        return AgentTracer(agent_id="test-agent", output_dir=tmp_path)

    def test_start_session_records_event(self, tracer):
        event = tracer.start_session()
        assert event.event_type == EventType.SESSION_START
        assert tracer.event_count == 1

    def test_record_tool_call_hashes_inputs(self, tracer):
        event = tracer.record_tool_call("search", input_text="q")
        assert event.input_hash == hash_text("q")
        assert event.tool_name == "search"
        assert event.event_type == EventType.TOOL_CALL

    def test_record_never_stores_raw_text(self, tracer):
        event = tracer.record_tool_call(
            "search", input_text="secret query", output_text="secret result"
        )
        d = event.to_dict()
        assert "secret query" not in json.dumps(d)
        assert "secret result" not in json.dumps(d)

    def test_record_hashes_output_text(self, tracer):
        event = tracer.record_tool_call("search", output_text="some output")
        assert event.output_hash == hash_text("some output")

    def test_record_explicit_output_hash_wins(self, tracer):
        event = tracer.record_tool_call("search", output_text="abc", output_hash="xyz")
        assert event.output_hash == "xyz"

    def test_record_stores_metadata(self, tracer):
        event = tracer.record_tool_call("search", metadata={"a": 1})
        assert event.metadata == {"a": 1}

    def test_record_defaults_to_allow(self, tracer):
        event = tracer.record_tool_call("search")
        assert event.policy_decision == PolicyDecision.ALLOW

    def test_record_decision(self, tracer):
        event = tracer.record_decision("approve", risk_score=10.0)
        assert event.event_type == EventType.DECISION
        assert event.risk_score == 10.0

    def test_record_error(self, tracer):
        event = tracer.record_error(action="tool_failed")
        assert event.event_type == EventType.ERROR
        assert event.policy_decision == PolicyDecision.DENY
        assert event.risk_score == 50.0

    def test_event_hash_chain(self, tracer):
        tracer.record_tool_call("a")
        tracer.record_tool_call("b")
        assert tracer.events[0].prev_hash == ""
        assert tracer.events[1].prev_hash == tracer.events[0].event_hash

    def test_all_event_types_recordable(self, tracer):
        for event_type in EventType:
            event = tracer.record(event_type, action=f"test-{event_type.value}")
            assert event.event_type == event_type

    def test_custom_session_id(self, tmp_path):
        tracer = AgentTracer(session_id="abc-123", output_dir=tmp_path)
        assert tracer.session_id == "abc-123"

    def test_end_session_writes_jsonl(self, tracer):
        tracer.start_session()
        tracer.record_tool_call("search", input_text="q")
        path = tracer.end_session()
        assert path is not None
        assert path.exists()
        lines = path.read_text().splitlines()
        assert len(lines) == 3

    def test_end_session_no_flush(self, tracer):
        path = tracer.end_session(flush=False)
        assert path is None
        assert tracer.event_count == 1

    def test_flush_returns_bundle_path(self, tracer):
        tracer.record_tool_call("search")
        path = tracer.flush()
        assert path.exists()
        assert tracer.bundle_path == path

    def test_verify_valid_bundle(self, tracer):
        tracer.start_session()
        tracer.record_tool_call("search", input_text="q")
        path = tracer.end_session()
        assert path is not None
        ok, errors = tracer.verify(path)
        assert ok is True
        assert errors == []

    def test_verify_tampered_bundle_fails(self, tracer):
        tracer.start_session()
        tracer.record_tool_call("search", input_text="q")
        path = tracer.end_session()
        assert path is not None
        lines = path.read_text().splitlines()
        data = json.loads(lines[1])
        data["action"] = "tampered"
        lines[1] = json.dumps(data)
        path.write_text("\n".join(lines) + "\n")
        ok, errors = tracer.verify(path)
        assert ok is False
        assert errors

    def test_verify_missing_file(self, tracer):
        ok, errors = tracer.verify("/nonexistent/bundle.jsonl")
        assert ok is False
        assert errors

    def test_verify_invalid_json(self, tracer, tmp_path):
        bad = tmp_path / "bad.jsonl"
        bad.write_text("{not json}\n")
        ok, errors = tracer.verify(bad)
        assert ok is False
        assert errors

    def test_verify_prev_hash_mismatch(self, tracer, tmp_path):
        event = TraceEvent(agent_id="x")
        event.seal()
        path = tmp_path / "bundle.jsonl"
        path.write_text(json.dumps(event.to_dict()) + "\n" + json.dumps(event.to_dict()) + "\n")
        ok, errors = tracer.verify(path)
        assert ok is False
        assert any("prev_hash" in e for e in errors)


# ── trace_tool tests ─────────────────────────

class TestTraceTool:
    @pytest.fixture
    def tracer(self, tmp_path):
        return AgentTracer(agent_id="test-agent", output_dir=tmp_path)

    def test_trace_tool_records_tool_call(self, tracer):
        with tracer.trace_tool("search", input_text="q") as t:
            t.output_text = "some result"
        assert t.event is not None
        assert t.event.event_type == EventType.TOOL_CALL
        assert t.event.tool_name == "search"
        assert t.event.input_hash == hash_text("q")
        assert t.event.output_hash == hash_text("some result")
        assert t.duration_ms >= 0.0

    def test_trace_tool_output_hash_wins(self, tracer):
        with tracer.trace_tool("search", input_text="q") as t:
            t.output_text = "abc"
            t.output_hash = "xyz"
        assert t.event is not None
        assert t.event.output_hash == "xyz"

    def test_trace_tool_records_duration_and_model(self, tracer):
        with tracer.trace_tool("search", model="gpt-4o", risk_score=10.0) as t:
            t.output_text = "ok"
        assert t.event is not None
        assert t.event.model == "gpt-4o"
        assert t.event.risk_score == 10.0
        assert t.event.duration_ms >= 0.0

    def test_trace_tool_exception_still_records_and_propagates(self, tracer):
        with pytest.raises(ValueError, match="boom"):
            with tracer.trace_tool("search", input_text="q") as t:
                raise ValueError("boom")
        assert t.event is not None
        assert tracer.event_count == 1
        assert t.event.event_type == EventType.ERROR
        assert t.event.tool_name == "search"
        assert t.event.input_hash == hash_text("q")
        assert t.event.policy_decision == PolicyDecision.DENY
        assert t.event.metadata["error"] == "ValueError"
        assert t.event.duration_ms >= 0.0

    def test_trace_tool_error_event_keeps_partial_output(self, tracer):
        with pytest.raises(ValueError, match="boom"):
            with tracer.trace_tool(
                "search", input_text="q", model="gpt-4o", risk_score=10.0
            ) as t:
                t.output_hash = hash_text("partial result")
                raise ValueError("boom")
        assert t.event is not None
        assert t.event.event_type == EventType.ERROR
        assert t.event.tool_name == "search"
        assert t.event.input_hash == hash_text("q")
        assert t.event.output_hash == hash_text("partial result")
        assert t.event.model == "gpt-4o"
        assert t.event.risk_score == 10.0
        assert t.event.policy_decision == PolicyDecision.DENY
        assert t.event.metadata["error"] == "ValueError"
        assert t.event.duration_ms >= 0.0

    def test_trace_tool_error_metadata_holds_only_exception_type(self, tracer):
        with pytest.raises(ValueError, match="sk-secret"):
            with tracer.trace_tool("search", input_text="q") as t:
                raise ValueError("sk-secret-token")
        assert t.event is not None
        assert t.event.event_type == EventType.ERROR
        assert t.event.metadata["error"] == "ValueError"
        assert "sk-secret-token" not in json.dumps(t.event.to_dict())


# ── ComplianceReport tests ─────────────────────────

class TestComplianceReport:
    @pytest.fixture
    def bundle(self, tmp_path):
        tracer = AgentTracer(agent_id="test-agent", output_dir=tmp_path)
        tracer.start_session()
        tracer.record_tool_call("search", input_text="q", risk_score=10.0)
        tracer.record_tool_call("search", input_text="q2", risk_score=90.0)
        tracer.record_tool_call("fetch", input_text="u", risk_score=5.0)
        tracer.record_decision("approve", risk_score=95.0)
        tracer.record_error(action="failed")
        return tracer.end_session()

    def test_report_counts_events(self, bundle):
        report = generate_report(bundle)
        assert report.event_count == 7

    def test_report_counts_by_type(self, bundle):
        report = generate_report(bundle)
        assert report.events_by_type[EventType.TOOL_CALL.value] == 3
        assert report.events_by_type[EventType.DECISION.value] == 1
        assert report.events_by_type[EventType.ERROR.value] == 1

    def test_report_counts_denied(self, bundle):
        report = generate_report(bundle)
        assert report.denied_count == 1

    def test_report_counts_high_risk(self, bundle):
        report = generate_report(bundle)
        assert report.high_risk_count == 2

    def test_report_counts_errors(self, bundle):
        report = generate_report(bundle)
        assert report.error_count == 1

    def test_report_tool_usage_counts(self, bundle):
        report = generate_report(bundle)
        assert report.tool_usage == {"search": 2, "fetch": 1}

    def test_report_top_tools(self, bundle):
        report = generate_report(bundle)
        assert report.top_tools == [("search", 2), ("fetch", 1)]

    def test_report_top_tools_empty_without_tool_calls(self, tmp_path):
        tracer = AgentTracer(agent_id="test-agent", output_dir=tmp_path)
        tracer.start_session()
        tracer.record_decision("approve")
        path = tracer.end_session()
        report = generate_report(path)
        assert report.top_tools == []

    def test_report_includes_agent_and_session(self, bundle):
        report = generate_report(bundle)
        assert report.agent_id == "test-agent"
        assert report.session_id

    def test_report_to_dict(self, bundle):
        report = generate_report(bundle)
        d = report.to_dict()
        assert "agent_id" in d
        assert "generated_at_utc" in d
        assert "compliance_verdict" in d

    def test_generate_report_function(self, bundle):
        report = generate_report(bundle)
        assert isinstance(report, ComplianceReport)

    def test_generate_report_empty_events(self, tmp_path):
        tracer = AgentTracer(agent_id="test-agent", output_dir=tmp_path)
        tracer.start_session()
        path = tracer.end_session()
        report = generate_report(path)
        assert report is not None
        assert report.event_count == 2
        assert report.compliance_verdict == "compliant"

    def test_generate_report_rejects_high_risk(self, bundle):
        report = generate_report(bundle)
        assert report.compliance_verdict == "review_required"

    def test_generate_report_rejects_unverified(self, tmp_path):
        path = tmp_path / "bundle.jsonl"
        path.write_text("{not json}\n")
        report = generate_report(path)
        assert report.compliance_verdict == "unverified"
        assert report.verified is False

    def test_report_compliance_verdict_compliant(self, tmp_path):
        tracer = AgentTracer(agent_id="test-agent", output_dir=tmp_path)
        tracer.start_session()
        tracer.record_tool_call("search", input_text="q")
        path = tracer.end_session()
        report = generate_report(path)
        assert report.verified is True
        assert report.high_risk_count == 0
        assert report.denied_count == 0
        assert report.compliance_verdict == "compliant"

    def test_report_requires_both_checks(self, tmp_path):
        tracer = AgentTracer(agent_id="test-agent", output_dir=tmp_path)
        tracer.start_session()
        tracer.record_tool_call("search", input_text="q", risk_score=90.0)
        path = tracer.end_session()
        report = generate_report(path)
        assert report.verified is True
        assert report.high_risk_count == 1
        assert report.compliance_verdict == "review_required"
