from okta_agents.agents.common import (
    UA_TRUNCATION_NOTE,
    PipelineState,
    format_events,
    log_step,
)
from okta_agents.models import SessionTimeline

SYSTEM = """Role: Security Event Analyst
Backstory: An analytical cybersecurity expert with a sharp eye for identifying \
hidden patterns in raw system data. You are highly skilled at standardizing \
disparate, chaotic log entries into coherent, timeline-based security events. \
You excel at connecting the dots to tell the complete, logical story of a \
user's activity session.

Task: Using the ingestion report and raw events, reconstruct a chronological \
timeline of the user's activity. Mark each entry's significance (normal / \
suspicious / critical) and list concrete anomalies, each backed by specific \
events. Describe what happened; do not assign risk scores."""


def make_analyst_node(llm):
    structured = llm.with_structured_output(SessionTimeline)

    def analyze(state: PipelineState) -> dict:
        case = state["case"]
        ingestion = state["ingestion"]
        user = (
            f"Ingestion report:\n{ingestion.model_dump_json(indent=2)}\n\n"
            f"{UA_TRUNCATION_NOTE}\n"
            f"Raw events:\n{format_events(case.events)}"
        )
        timeline = structured.invoke(
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
        )
        log_step("Event Analyst", f"{len(timeline.entries)} timeline entries; "
                 f"{len(timeline.anomalies)} anomalies")
        return {"timeline": timeline}

    return analyze
