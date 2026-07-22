import logging
from typing import TypedDict

from okta_agents.models import (
    CandidateCase,
    IngestionReport,
    OktaEvent,
    RemediationPlan,
    RiskAssessment,
    SessionTimeline,
    TriageDecision,
)

log = logging.getLogger("okta_agents")


class PipelineState(TypedDict, total=False):
    case: CandidateCase
    risk_threshold: int
    ingestion: IngestionReport
    timeline: SessionTimeline
    risk: RiskAssessment
    triage: TriageDecision
    remediation: RemediationPlan


def format_events(events: list[OktaEvent]) -> str:
    """One pipe-delimited line per event — compact enough for 75-event prompts.

    User-agent strings are truncated to 60 chars with a visible '…[truncated]'
    marker so agents don't mistake a cut-off UA for a malformed or suspicious
    one. See UA_TRUNCATION_NOTE, included in prompts that render these lines.
    """
    return "\n".join(
        f"{e.timestamp} | {e.event_type} | {e.outcome} | ip={e.ip_address} "
        f"| {e.city},{e.country} | app={e.app or '-'} | {e.display_message} "
        f"| ua={_ua(e.user_agent)}"
        for e in events
    )


def _ua(ua: str) -> str:
    return f"{ua[:60]}…[truncated]" if len(ua) > 60 else ua


# Prompt note so agents interpret truncated UA strings correctly.
UA_TRUNCATION_NOTE = (
    "Note: user-agent (ua=) strings are truncated to 60 characters and end with "
    "'…[truncated]' when cut — this is display formatting, not a malformed or "
    "suspicious client. Do not treat a truncated UA as an anomaly."
)


def format_docs(docs) -> str:
    return "\n\n".join(f"[{d.metadata.get('source', '?')}]\n{d.page_content}" for d in docs)


def log_step(agent: str, msg: str) -> None:
    log.info("[%s] %s", agent, msg)
