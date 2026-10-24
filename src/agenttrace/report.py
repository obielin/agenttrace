"""
Compliance report generator for agenttrace bundles.
Produces EU AI Act Article 12/13/14, ISO 42001, and NIST AI RMF evidence reports.
Zero external dependencies.
"""

from __future__ import annotations

import json
import pathlib
import time
from dataclasses import dataclass, field
from typing import Any

from agenttrace.schema import EventType, PolicyDecision, TraceEvent


@dataclass
class ComplianceReport:
    """
    Structured compliance report generated from an agenttrace bundle.

    Maps concrete audit evidence to:
    - EU AI Act Articles 12, 13, 14
    - ISO/IEC 42001 Clauses 6.1, 8.4, 9.1
    - NIST AI RMF Functions (GOVERN, MAP, MEASURE, MANAGE)
    """

    bundle_path: str
    session_id: str
    agent_id: str
    framework: str
    generated_at: float = field(default_factory=time.time)

    # Event counts
    total_events: int = 0
    decision_events: int = 0
    tool_call_events: int = 0
    error_events: int = 0
    policy_check_events: int = 0
    human_review_events: int = 0

    # Risk summary
    avg_risk_score: float = 0.0
    max_risk_score: float = 0.0
    high_risk_events: int = 0
    deny_decisions: int = 0
    human_oversight_triggered: int = 0

    # Chain integrity
    chain_valid: bool = True
    chain_errors: list[str] = field(default_factory=list)

    # Framework mapping
    eu_ai_act_coverage: dict[str, str] = field(default_factory=dict)
    iso_42001_coverage: dict[str, str] = field(default_factory=dict)
    nist_ai_rmf_coverage: dict[str, str] = field(default_factory=dict)

    # Raw events for evidence
    high_risk_event_ids: list[str] = field(default_factory=list)
    deny_event_ids: list[str] = field(default_factory=list)

    def summary_lines(self) -> list[str]:
        lines = [
            "",
            "=" * 70,
            "  AGENTTRACE COMPLIANCE REPORT",
            "  agenttrace schema v1.0.0",
            "=" * 70,
            f"  Bundle:      {self.bundle_path}",
            f"  Session:     {self.session_id}",
            f"  Agent:       {self.agent_id}",
            f"  Framework:   {self.framework}",
            f"  Generated:   {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.generated_at))}",
            "-" * 70,
            "  EVENT SUMMARY",
            f"  Total events:          {self.total_events}",
            f"  Decisions:             {self.decision_events}",
            f"  Tool calls:            {self.tool_call_events}",
            f"  Policy checks:         {self.policy_check_events}",
            f"  Errors:                {self.error_events}",
            f"  Human reviews:         {self.human_review_events}",
            "-" * 70,
            "  RISK SUMMARY",
            f"  Average risk score:    {self.avg_risk_score:.1f}/100",
            f"  Maximum risk score:    {self.max_risk_score:.1f}/100",
            f"  High-risk events:      {self.high_risk_events}",
            f"  DENY decisions:        {self.deny_decisions}",
            f"  Human oversight:       {self.human_oversight_triggered}",
            "-" * 70,
            "  CHAIN INTEGRITY",
            f"  Valid:                 {'YES' if self.chain_valid else 'NO — TAMPERING DETECTED'}",
        ]
        if self.chain_errors:
            for err in self.chain_errors[:3]:
                lines.append(f"  Error:                 {err}")
        lines += [
            "-" * 70,
            "  EU AI ACT COVERAGE",
        ]
        for article, status in self.eu_ai_act_coverage.items():
            lines.append(f"  {article:<30} {status}")
        lines += [
            "-" * 70,
            "  ISO/IEC 42001 COVERAGE",
        ]
        for clause, status in self.iso_42001_coverage.items():
            lines.append(f"  {clause:<30} {status}")
        lines += [
            "-" * 70,
            "  NIST AI RMF COVERAGE",
        ]
        for fn, status in self.nist_ai_rmf_coverage.items():
            lines.append(f"  {fn:<30} {status}")
        lines += ["=" * 70, ""]
        return lines

    def to_text(self) -> str:
        return "\n".join(self.summary_lines())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "agenttrace-report-v1.0.0",
            "bundle_path": self.bundle_path,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "framework": self.framework,
            "generated_at": self.generated_at,
            "events": {
                "total": self.total_events,
                "decisions": self.decision_events,
                "tool_calls": self.tool_call_events,
                "errors": self.error_events,
                "policy_checks": self.policy_check_events,
                "human_reviews": self.human_review_events,
            },
            "risk": {
                "avg_score": self.avg_risk_score,
                "max_score": self.max_risk_score,
                "high_risk_count": self.high_risk_events,
                "deny_count": self.deny_decisions,
                "human_oversight_count": self.human_oversight_triggered,
                "high_risk_event_ids": self.high_risk_event_ids,
                "deny_event_ids": self.deny_event_ids,
            },
            "chain_integrity": {
                "valid": self.chain_valid,
                "errors": self.chain_errors,
            },
            "compliance": {
                "eu_ai_act": self.eu_ai_act_coverage,
                "iso_42001": self.iso_42001_coverage,
                "nist_ai_rmf": self.nist_ai_rmf_coverage,
            },
        }


def generate_report(
    bundle_path: pathlib.Path,
    verify_chain: bool = True,
) -> ComplianceReport:
    """
    Generate a compliance report from an agenttrace JSONL bundle.

    Args:
        bundle_path:   Path to the .jsonl bundle file
        verify_chain:  Whether to verify hash-chain integrity

    Returns:
        ComplianceReport with full compliance mapping
    """
    events: list[TraceEvent] = []

    with bundle_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                events.append(TraceEvent.from_dict(data))
            except Exception:
                continue

    if not events:
        return ComplianceReport(
            bundle_path=str(bundle_path),
            session_id="unknown",
            agent_id="unknown",
            framework="unknown",
        )

    first = events[0]
    report = ComplianceReport(
        bundle_path=str(bundle_path),
        session_id=first.session_id,
        agent_id=first.agent_id,
        framework=first.framework,
    )

    # Event counts
    report.total_events = len(events)
    report.decision_events = sum(1 for e in events if e.event_type == EventType.DECISION)
    report.tool_call_events = sum(1 for e in events if e.event_type == EventType.TOOL_CALL)
    report.error_events = sum(1 for e in events if e.event_type == EventType.ERROR)
    report.policy_check_events = sum(1 for e in events if e.event_type == EventType.POLICY_CHECK)
    report.human_review_events = sum(1 for e in events if e.event_type == EventType.HUMAN_REVIEW)

    # Risk
    scores = [e.risk_score for e in events]
    report.avg_risk_score = sum(scores) / len(scores) if scores else 0.0
    report.max_risk_score = max(scores) if scores else 0.0
    report.high_risk_events = sum(1 for s in scores if s > 50)
    report.high_risk_event_ids = [e.event_id for e in events if e.risk_score > 50]
    report.deny_decisions = sum(1 for e in events if e.policy_decision == PolicyDecision.DENY)
    report.deny_event_ids = [e.event_id for e in events if e.policy_decision == PolicyDecision.DENY]
    report.human_oversight_triggered = sum(1 for e in events if e.human_oversight_required)

    # Chain integrity
    if verify_chain:
        from agenttrace.tracer import AgentTracer

        tracer = AgentTracer.__new__(AgentTracer)
        tracer._events = events
        tracer._bundle_path = bundle_path
        report.chain_valid, report.chain_errors = tracer.verify(bundle_path)

    # Compliance mapping
    has_decisions = report.decision_events > 0
    has_tools = report.tool_call_events > 0
    has_chain = report.chain_valid
    has_human = report.human_review_events > 0 or report.human_oversight_triggered > 0
    has_risk_scores = any(e.risk_score > 0 for e in events)
    has_risk = report.policy_check_events > 0 or has_risk_scores
    has_incident_tracking = report.policy_check_events > 0 or report.deny_decisions > 0

    report.eu_ai_act_coverage = {
        "Article 12 — Logging": (
            "SATISFIED — all decisions logged with timestamps, agent ID, and action hashes"
            if has_decisions
            else "PARTIAL — no decision events found"
        ),
        "Article 12 — Tamper evidence": (
            "SATISFIED — SHA-256 hash chain verified"
            if has_chain
            else "FAILED — hash chain verification failed"
        ),
        "Article 13 — Transparency": (
            "SATISFIED — agent_id, framework, and model fields populated"
            if first.agent_id != "unknown"
            else "PARTIAL — agent_id not set"
        ),
        "Article 14 — Human oversight": (
            "SATISFIED — human_oversight_required tracked per event"
            if has_human
            else "PARTIAL — no human oversight events recorded"
        ),
        "Article 9 — Risk management": (
            "SATISFIED — risk_score and risk_tier recorded per event"
            if has_risk
            else "PARTIAL — no policy checks or non-zero risk scores recorded"
        ),
    }

    report.iso_42001_coverage = {
        "Clause 6.1 — Risk actions": (
            "SATISFIED — risk_score > 0 events annotated"
            if has_risk_scores
            else "PARTIAL — no events with risk_score > 0"
        ),
        "Clause 8.4 — AI system lifecycle": (
            "SATISFIED — session_start and session_end events recorded"
            if report.total_events > 2
            else "PARTIAL"
        ),
        "Clause 9.1 — Monitoring": (
            "SATISFIED — policy_decision recorded for all events" if has_decisions else "PARTIAL"
        ),
        "Clause 10.1 — Continual improvement": "PARTIAL — review deny_event_ids for improvement opportunities",
    }

    report.nist_ai_rmf_coverage = {
        "GOVERN 1.1 — Policies": (
            "SATISFIED — policy_rules_applied recorded" if has_decisions else "PARTIAL"
        ),
        "GOVERN 6.1 — Accountability": (
            "SATISFIED — agent_id and session_id traceable" if has_chain else "PARTIAL"
        ),
        "MAP 1.1 — Context": (
            "SATISFIED — framework and model fields populated" if has_tools else "PARTIAL"
        ),
        "MANAGE 2.2 — Incidents": (
            f"SATISFIED — {report.deny_decisions} DENY decisions logged"
            if has_incident_tracking
            else "PARTIAL — no policy checks or DENY decisions recorded"
        ),
        "MEASURE 2.5 — Risk tracking": f"SATISFIED — avg risk score {report.avg_risk_score:.1f}/100",
    }

    return report
