"""LangGraph StateGraph wiring the five agents with a conditional triage edge."""

from typing import Literal

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from okta_agents.agents.common import PipelineState
from okta_agents.agents.event_analyst import make_analyst_node
from okta_agents.agents.ingestion import make_ingestion_node
from okta_agents.agents.remediation import make_remediation_node
from okta_agents.agents.threat_intel import make_threat_intel_node
from okta_agents.agents.triage import make_triage_node


def _route_triage(state: PipelineState) -> Literal["remediate", "__end__"]:
    return "remediate" if state["triage"].decision == "escalate" else END


def build_graph(llm, retriever, checkpointer=None):
    builder = StateGraph(PipelineState)
    builder.add_node("ingest", make_ingestion_node(llm))
    builder.add_node("analyze", make_analyst_node(llm))
    builder.add_node("assess", make_threat_intel_node(llm, retriever))
    builder.add_node("triage", make_triage_node(llm))
    builder.add_node("remediate", make_remediation_node(llm, retriever))

    builder.add_edge(START, "ingest")
    builder.add_edge("ingest", "analyze")
    builder.add_edge("analyze", "assess")
    builder.add_edge("assess", "triage")
    builder.add_conditional_edges("triage", _route_triage,
                                  {"remediate": "remediate", END: END})
    builder.add_edge("remediate", END)

    return builder.compile(checkpointer=checkpointer or InMemorySaver())
