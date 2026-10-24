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
            agent_id="test-agent",
            event_type=EventType.DECISION,
            action="plan",
            risk_score=25.0,
        )
        event.seal()
        d = event.to_dict()
        restored = TraceEvent.from_dict(d)
        assert restored.agent_id == event.agent_id
        assert restored.event_type == event.event_type
        assert restored.risk_score == event.risk_score
        assert restored.event_hash == event.event_hash

    def test_event_type_enum(self):
        event = TraceEvent(event_type=EventType.TOOL_CALL)
        assert event.event_type == EventType.TOOL_CALL

    def test_policy_decision_enum(self):
        event = TraceEvent(policy_decision=PolicyDecision.DENY)
        assert event.policy_decision == PolicyDecision.DENY

    def test_risk_tier_enum(self):
        event = TraceEvent(risk_tier=RiskTier.HIGH)
        assert event.risk_tier == RiskTier.HIGH

    def test_repr(self):
        event = TraceEvent(agent_id="myagent", event_type=EventType.DECISION)
        assert "myagent" in repr(event)
        assert "decision" in repr(event)


# ── AgentTracer tests ──────────────────────────────


class TestAgentTracer:
    @pytest.fixture
    def tracer(self, tmp_path):
        return AgentTracer(
            agent_id="test-agent",
            framework="custom",
            output_dir=tmp_path,
        )

    def test_initial_state(self, tracer):
        assert tracer.event_count == 0
        assert tracer.session_id
        assert tracer.agent_id == "test-agent"

    def test_start_session_creates_event(self, tracer):
        tracer.start_session()
        assert tracer.event_count == 1
        assert tracer.events[0].event_type == EventType.SESSION_START

    def test_record_creates_event(self, tracer):
        tracer.record(EventType.DECISION, action="plan")
        assert tracer.event_count == 1

    def test_record_tool_call(self, tracer):
        event = tracer.record_tool_call(tool="web_search", input_text="AI Act")
        assert event.event_type == EventType.TOOL_CALL
        assert event.tool_name == "web_search"
        assert event.input_hash != ""

    def test_record_decision(self, tracer):
        event = tracer.record_decision(action="summarise", risk_score=10.0)
        assert event.event_type == EventType.DECISION
        assert event.risk_score == 10.0

    def test_record_error(self, tracer):
        event = tracer.record_error(action="tool_failed")
        assert event.event_type == EventType.ERROR
        assert event.policy_decision == PolicyDecision.DENY

    def test_hash_chain_links_events(self, tracer):
        tracer.start_session()
        tracer.record_tool_call(tool="search")
        tracer.record_decision(action="plan")
        events = tracer.events
        assert events[1].prev_hash == events[0].event_hash
        assert events[2].prev_hash == events[1].event_hash

    def test_end_session_creates_event(self, tracer):
        tracer.start_session()
        tracer.end_session(flush=False)
        types = [e.event_type for e in tracer.events]
        assert EventType.SESSION_START in types
        assert EventType.SESSION_END in types

    def test_flush_creates_jsonl_file(self, tracer):
        tracer.start_session()
        tracer.record_decision(action="test")
        path = tracer.flush()
        assert path.exists()
        assert path.suffix == ".jsonl"

    def test_flush_file_is_valid_jsonl(self, tracer):
        tracer.start_session()
        tracer.record_tool_call(tool="search")
        path = tracer.flush()
        lines = path.read_text().strip().split("\n")
        for line in lines:
            data = json.loads(line)
            assert "event_id" in data

    def test_verify_valid_bundle(self, tracer):
        tracer.start_session()
        tracer.record_decision(action="plan")
        tracer.record_tool_call(tool="search")
        path = tracer.end_session(flush=True)
        valid, errors = tracer.verify(path)
        assert valid is True
        assert errors == []

    def test_verify_tampered_bundle(self, tracer, tmp_path):
        tracer.start_session()
        tracer.record_decision(action="plan")
        path = tracer.flush()
        # Tamper with the bundle
        lines = path.read_text().strip().split("\n")
        data = json.loads(lines[0])
        data["action"] = "TAMPERED"
        lines[0] = json.dumps(data)
        path.write_text("\n".join(lines))
        valid, errors = tracer.verify(path)
        assert valid is False
        assert len(errors) > 0

    def test_auto_compliance_annotation(self, tracer):
        event = tracer.record(EventType.DECISION, action="plan")
        assert event.eu_ai_act_article == "Article 12"
        assert event.nist_ai_rmf_function == "GOVERN 1.1"

    def test_hash_text(self):
        h = hash_text("hello world")
        assert len(h) == 64
        assert hash_text("hello world") == h
        assert hash_text("different") != h

    def test_end_session_returns_path(self, tracer):
        tracer.start_session()
        path = tracer.end_session()
        assert path is not None
        assert path.exists()

    def test_events_property_returns_copy(self, tracer):
        tracer.record_decision(action="x")
        events = tracer.events
        events.clear()
        assert tracer.event_count == 1

    def test_custom_session_id(self, tmp_path):
        tracer = AgentTracer(
            agent_id="agent",
            session_id="my-custom-session",
            output_dir=tmp_path,
        )
        assert tracer.session_id == "my-custom-session"

    def test_all_event_types_recordable(self, tracer):
        for event_type in EventType:
            tracer.record(event_type, action=f"test-{event_type.value}")
        assert tracer.event_count == len(EventType)

    def test_metadata_preserved(self, tracer):
        event = tracer.record(EventType.DECISION, action="x", metadata={"key": "value"})
        assert event.metadata["key"] == "value"


# ── ComplianceReport tests ─────────────────────────


class TestComplianceReport:
    @pytest.fixture
    def bundle(self, tmp_path):
        tracer = AgentTracer(
            agent_id="report-agent",
            framework="langgraph",
            output_dir=tmp_path,
        )
        tracer.start_session()
        tracer.record_tool_call(tool="search", input_text="test", risk_score=10.0)
        tracer.record_decision(action="plan", risk_score=20.0)
        tracer.record(EventType.POLICY_CHECK, action="check", risk_score=5.0)
        tracer.record_error(action="failed")
        tracer.end_session()
        return tracer.bundle_path

    def test_generate_report_returns_report(self, bundle):
        report = generate_report(bundle)
        assert isinstance(report, ComplianceReport)

    def test_report_event_counts(self, bundle):
        report = generate_report(bundle)
        assert report.total_events > 0
        assert report.tool_call_events == 1
        assert report.decision_events == 1
        assert report.error_events == 1

    def test_report_agent_id(self, bundle):
        report = generate_report(bundle)
        assert report.agent_id == "report-agent"

    def test_report_framework(self, bundle):
        report = generate_report(bundle)
        assert report.framework == "langgraph"

    def test_report_chain_valid(self, bundle):
        report = generate_report(bundle)
        assert report.chain_valid is True

    def test_report_eu_ai_act_coverage(self, bundle):
        report = generate_report(bundle)
        assert "Article 12 — Logging" in report.eu_ai_act_coverage

    def test_report_iso_coverage(self, bundle):
        report = generate_report(bundle)
        assert len(report.iso_42001_coverage) > 0

    def test_report_nist_coverage(self, bundle):
        report = generate_report(bundle)
        assert len(report.nist_ai_rmf_coverage) > 0

    def test_report_to_text(self, bundle):
        report = generate_report(bundle)
        text = report.to_text()
        assert "AGENTTRACE COMPLIANCE REPORT" in text
        assert "EU AI ACT" in text
        assert "NIST AI RMF" in text

    def test_report_to_dict(self, bundle):
        report = generate_report(bundle)
        d = report.to_dict()
        assert "schema" in d
        assert "events" in d
        assert "risk" in d
        assert "compliance" in d
        assert "chain_integrity" in d

    def test_report_risk_scores(self, bundle):
        report = generate_report(bundle)
        assert report.avg_risk_score >= 0
        assert report.max_risk_score >= 0

    def test_report_deny_count(self, tmp_path):
        tracer = AgentTracer(agent_id="a", output_dir=tmp_path)
        tracer.start_session()
        tracer.record_decision(action="x", policy_decision=PolicyDecision.DENY)
        tracer.record_decision(action="y", policy_decision=PolicyDecision.DENY)
        path = tracer.end_session()
        report = generate_report(path)
        assert report.deny_decisions == 2
        assert len(report.deny_event_ids) == 2

    def test_report_risk_clauses_partial_without_evidence(self, tmp_path):
        tracer = AgentTracer(agent_id="a", output_dir=tmp_path)
        tracer.start_session()
        path = tracer.end_session()
        report = generate_report(path)
        assert report.eu_ai_act_coverage["Article 9 — Risk management"].startswith("PARTIAL")
        assert report.iso_42001_coverage["Clause 6.1 — Risk actions"].startswith("PARTIAL")
        assert report.nist_ai_rmf_coverage["MANAGE 2.2 — Incidents"].startswith("PARTIAL")

    def test_report_risk_clauses_satisfied_with_evidence(self, bundle):
        report = generate_report(bundle)
        assert report.eu_ai_act_coverage["Article 9 — Risk management"].startswith("SATISFIED")
        assert report.iso_42001_coverage["Clause 6.1 — Risk actions"].startswith("SATISFIED")
        assert report.nist_ai_rmf_coverage["MANAGE 2.2 — Incidents"].startswith("SATISFIED")
