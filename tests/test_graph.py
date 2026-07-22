from okta_agents.graph import build_graph
from okta_agents.models import (
    IngestionReport,
    RemediationPlan,
    RiskAssessment,
    SessionTimeline,
    TriageDecision,
)
from tests.fakes import FakeStructuredModel, fake_retriever
from tests.test_agent_nodes import INGESTION, PLAN, RISK, TIMELINE, make_case


def _llm(decision: str) -> FakeStructuredModel:
    return FakeStructuredModel({
        IngestionReport: INGESTION,
        SessionTimeline: TIMELINE,
        RiskAssessment: RISK,
        TriageDecision: TriageDecision(decision=decision, rationale="r",
                                       business_impact="b"),
        RemediationPlan: PLAN,
    })


def _run(decision: str):
    llm = _llm(decision)
    graph = build_graph(llm, fake_retriever())
    state = graph.invoke(
        {"case": make_case(), "risk_threshold": 70},
        config={"configurable": {"thread_id": "t1"}},
    )
    return state, llm


def test_escalate_path_runs_all_five_agents():
    state, llm = _run("escalate")
    assert state["triage"].decision == "escalate"
    assert state["remediation"] == PLAN
    assert [c.__name__ for c in llm.calls] == [
        "IngestionReport", "SessionTimeline", "RiskAssessment",
        "TriageDecision", "RemediationPlan",
    ]


def test_dismiss_path_skips_remediation():
    state, llm = _run("dismiss")
    assert state["triage"].decision == "dismiss"
    assert "remediation" not in state
    assert RemediationPlan not in llm.calls
