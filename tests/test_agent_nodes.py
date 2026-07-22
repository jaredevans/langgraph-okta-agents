from okta_agents.agents.common import format_events
from okta_agents.agents.event_analyst import make_analyst_node
from okta_agents.agents.ingestion import make_ingestion_node
from okta_agents.models import (
    CandidateCase,
    IngestionReport,
    SessionTimeline,
    TimelineEntry,
)
from tests.fakes import FakeStructuredModel
from tests.test_models import make_event


def make_case(**overrides) -> CandidateCase:
    base = dict(
        case_id="case-001-test",
        user_email="test.user@example.edu",
        user_display_name="Test User",
        window_start="2026-07-21T00:00:00.000Z",
        window_end="2026-07-21T01:00:00.000Z",
        signals={"failed_auth": 8.0},
        signal_details=["8 failed authentication events"],
        events=[make_event(), make_event(outcome="FAILURE")],
    )
    base.update(overrides)
    return CandidateCase(**base)


INGESTION = IngestionReport(
    total_events=2,
    time_range="2026-07-21T00:00 to 01:00",
    event_type_summary="2x user.authentication.sso",
    data_integrity_notes=[],
    notable_observations=["1 failure"],
)

TIMELINE = SessionTimeline(
    narrative="User failed then succeeded.",
    entries=[TimelineEntry(timestamp="2026-07-21T00:52:55.748Z",
                           description="SSO success", significance="normal")],
    anomalies=["failure preceding success"],
)


def test_format_events_is_compact_and_complete():
    text = format_events([make_event()])
    assert "user.authentication.sso" in text
    assert "134.231.2.45" in text
    assert "United States" in text
    assert "\n" not in text.strip()  # one line per event


def test_format_events_marks_truncated_user_agent():
    long_ua = "Mozilla/5.0 " + "X" * 100
    text = format_events([make_event(user_agent=long_ua)])
    assert "…[truncated]" in text  # cut UA is visibly marked
    short = format_events([make_event(user_agent="curl/8.0")])
    assert "…[truncated]" not in short  # short UA left intact


def test_ingestion_node_returns_report_and_prompts_with_events():
    llm = FakeStructuredModel({IngestionReport: INGESTION})
    node = make_ingestion_node(llm)
    result = node({"case": make_case()})
    assert result == {"ingestion": INGESTION}
    assert llm.calls == [IngestionReport]


def test_analyst_node_returns_timeline():
    llm = FakeStructuredModel({SessionTimeline: TIMELINE})
    node = make_analyst_node(llm)
    result = node({"case": make_case(), "ingestion": INGESTION})
    assert result == {"timeline": TIMELINE}


from okta_agents.agents.remediation import make_remediation_node
from okta_agents.agents.threat_intel import make_threat_intel_node
from okta_agents.agents.triage import make_triage_node
from okta_agents.models import (
    PatternMatch,
    RemediationPlan,
    RemediationStep,
    RiskAssessment,
    TriageDecision,
)
from tests.fakes import fake_retriever

RISK = RiskAssessment(
    risk_score=85,
    matched_patterns=[PatternMatch(pattern_name="mfa_fatigue", confidence="high",
                                   evidence=["4 push denials"])],
    reasoning="Push bombing pattern.",
    kb_sources=["mfa-fatigue.md"],
)

TRIAGE_ESCALATE = TriageDecision(decision="escalate", rationale="High risk",
                                 business_impact="Account takeover risk")

PLAN = RemediationPlan(
    summary="Contain compromised account",
    priority="high",
    steps=[RemediationStep(order=1, action="Suspend user", detail="Okta admin console")],
)


def test_threat_intel_node_queries_retriever_and_returns_risk():
    llm = FakeStructuredModel({RiskAssessment: RISK})
    retriever = fake_retriever()
    node = make_threat_intel_node(llm, retriever)
    result = node({"case": make_case(), "ingestion": INGESTION, "timeline": TIMELINE})
    assert result == {"risk": RISK}


def test_triage_node_receives_threshold():
    llm = FakeStructuredModel({TriageDecision: TRIAGE_ESCALATE})
    node = make_triage_node(llm)
    result = node({"case": make_case(), "timeline": TIMELINE, "risk": RISK,
                   "risk_threshold": 70})
    assert result == {"triage": TRIAGE_ESCALATE}


def test_remediation_node_returns_plan():
    llm = FakeStructuredModel({RemediationPlan: PLAN})
    node = make_remediation_node(llm, fake_retriever())
    result = node({"case": make_case(), "timeline": TIMELINE, "risk": RISK,
                   "triage": TRIAGE_ESCALATE})
    assert result == {"remediation": PLAN}


def test_ingestion_prompt_includes_signal_evidence():
    llm = FakeStructuredModel({IngestionReport: INGESTION})
    case = make_case(signal_details=["2 events on flagged IP block 35.33.x.x (7 users targeted)"])
    make_ingestion_node(llm)({"case": case})
    assert any("35.33.x.x (7 users targeted)" in str(p) for p in llm.prompts)


def test_threat_intel_prompt_and_query_include_signal_evidence():
    from okta_agents.models import RiskAssessment as _RA
    llm = FakeStructuredModel({_RA: RISK})
    queries = []
    from langchain_core.runnables import RunnableLambda
    from langchain_core.documents import Document

    def _capture(q):
        queries.append(q)
        return [Document(page_content="x", metadata={"source": "kb"})]

    case = make_case(signal_details=["2 events on flagged IP block 35.33.x.x (7 users targeted)"])
    node = make_threat_intel_node(llm, RunnableLambda(_capture))
    node({"case": case, "ingestion": INGESTION, "timeline": TIMELINE})
    assert any("35.33.x.x" in q for q in queries)  # retrieval sees campaign context
    assert any("35.33.x.x (7 users targeted)" in str(p) for p in llm.prompts)
