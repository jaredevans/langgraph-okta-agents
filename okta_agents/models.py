from typing import Literal

from pydantic import BaseModel, Field


class OktaEvent(BaseModel):
    timestamp: str
    event_type: str
    display_message: str
    outcome: str
    actor_name: str
    actor_email: str
    ip_address: str
    country: str
    city: str
    user_agent: str
    app: str = ""


class CandidateCase(BaseModel):
    case_id: str
    user_email: str
    user_display_name: str
    window_start: str
    window_end: str
    signals: dict[str, float]
    signal_details: list[str]
    events: list[OktaEvent]


class IngestionReport(BaseModel):
    """Structured output of the Okta Telemetry Ingestion Worker."""

    total_events: int = Field(description="Number of events in this case bundle")
    time_range: str = Field(description="First to last event timestamp")
    event_type_summary: str = Field(description="Concise summary of event type distribution")
    data_integrity_notes: list[str] = Field(
        description="Missing/blank/corrupt fields observed in the raw events"
    )
    notable_observations: list[str] = Field(
        description="Facts worth analyst attention (IPs, geos, clients), no speculation"
    )


class TimelineEntry(BaseModel):
    timestamp: str
    description: str
    significance: Literal["normal", "suspicious", "critical"]


class SessionTimeline(BaseModel):
    """Structured output of the Security Event Analyst."""

    narrative: str = Field(description="The coherent story of the user's activity")
    entries: list[TimelineEntry]
    anomalies: list[str] = Field(description="Specific anomalies with supporting events")


class PatternMatch(BaseModel):
    pattern_name: str
    confidence: Literal["low", "medium", "high"]
    evidence: list[str]


class RiskAssessment(BaseModel):
    """Structured output of the Threat Intelligence Specialist."""

    risk_score: int = Field(ge=0, le=100)
    matched_patterns: list[PatternMatch]
    reasoning: str
    kb_sources: list[str] = Field(description="Knowledge-base sources consulted")


class TriageDecision(BaseModel):
    """Structured output of the Incident Triage Coordinator."""

    decision: Literal["escalate", "dismiss"]
    rationale: str
    business_impact: str


class RemediationStep(BaseModel):
    order: int
    action: str
    detail: str


class RemediationPlan(BaseModel):
    """Structured output of the Incident Remediation Executor. ADVISORY ONLY."""

    summary: str
    priority: Literal["low", "medium", "high", "critical"]
    steps: list[RemediationStep]


class IncidentTicket(BaseModel):
    case_id: str
    user_email: str
    status: Literal["escalated", "dismissed", "error"]
    signals: dict[str, float]
    ingestion: IngestionReport | None = None
    timeline: SessionTimeline | None = None
    risk: RiskAssessment | None = None
    triage: TriageDecision | None = None
    remediation: RemediationPlan | None = None
    error: str | None = None
