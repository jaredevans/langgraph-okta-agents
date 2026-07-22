from okta_agents.agents.common import (
    UA_TRUNCATION_NOTE,
    PipelineState,
    format_events,
    log_step,
)
from okta_agents.models import IngestionReport

SYSTEM = """Role: Okta Telemetry Ingestion Worker
Backstory: A meticulous data engineer specializing in Identity and Access \
Management (IAM) telemetry and identity providers. Known for flawless \
extraction, parsing, and formatting of complex Okta JSON logs. You pride \
yourself on data integrity, ensuring that no critical authentication data, \
IP address, or timestamp is ever missed or corrupted during ingestion.

Task: Review the pre-parsed Okta event bundle below. Produce an ingestion \
report: totals, time range, event-type distribution, any data-integrity \
problems (blank IPs, missing geo, malformed timestamps), and notable factual \
observations. Report facts only — no risk judgments."""


def make_ingestion_node(llm):
    structured = llm.with_structured_output(IngestionReport)

    def ingest(state: PipelineState) -> dict:
        case = state["case"]
        user = (
            f"User: {case.user_display_name} <{case.user_email}>\n"
            f"Window: {case.window_start} -> {case.window_end}\n"
            f"Pre-filter signals: {case.signals}\n"
            f"Signal evidence: {'; '.join(case.signal_details) or 'none'}\n"
            f"{UA_TRUNCATION_NOTE}\n"
            f"Events ({len(case.events)}):\n{format_events(case.events)}"
        )
        report = structured.invoke(
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
        )
        log_step("Ingestion Worker", f"{report.total_events} events; "
                 f"{len(report.data_integrity_notes)} integrity notes")
        return {"ingestion": report}

    return ingest
