import pytest
from pydantic import ValidationError

from okta_agents.models import (
    IncidentTicket,
    OktaEvent,
    PatternMatch,
    RiskAssessment,
    TriageDecision,
)


def make_event(**overrides) -> OktaEvent:
    base = dict(
        timestamp="2026-07-21T00:52:55.748Z",
        event_type="user.authentication.sso",
        display_message="User single sign on to app",
        outcome="SUCCESS",
        actor_name="Kris Williams",
        actor_email="kris.williams@example.edu",
        ip_address="134.231.2.45",
        country="United States",
        city="Washington",
        user_agent="Mozilla/5.0",
    )
    base.update(overrides)
    return OktaEvent(**base)


def test_risk_score_bounds():
    match = PatternMatch(pattern_name="password_spray", confidence="high", evidence=["x"])
    RiskAssessment(risk_score=100, matched_patterns=[match], reasoning="r", kb_sources=[])
    with pytest.raises(ValidationError):
        RiskAssessment(risk_score=101, matched_patterns=[], reasoning="r", kb_sources=[])
    with pytest.raises(ValidationError):
        RiskAssessment(risk_score=-1, matched_patterns=[], reasoning="r", kb_sources=[])


def test_triage_decision_literal():
    TriageDecision(decision="escalate", rationale="r", business_impact="b")
    with pytest.raises(ValidationError):
        TriageDecision(decision="maybe", rationale="r", business_impact="b")


def test_incident_ticket_round_trip():
    ticket = IncidentTicket(
        case_id="case-001",
        user_email="kris.williams@example.edu",
        status="dismissed",
        signals={"failed_auth": 3.0},
    )
    restored = IncidentTicket.model_validate_json(ticket.model_dump_json())
    assert restored == ticket
    assert restored.remediation is None
