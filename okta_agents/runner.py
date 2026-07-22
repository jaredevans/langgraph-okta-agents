"""Orchestrates prefilter -> per-case graph -> reports. Dependencies injected."""

import logging
from datetime import datetime, timezone

from okta_agents.config import Settings
from okta_agents.graph import build_graph
from okta_agents.models import IncidentTicket
from okta_agents.prefilter import build_cases, compute_user_signals, load_logs
from okta_agents.report import (
    error_ticket,
    ticket_from_state,
    write_summary,
    write_ticket,
)

log = logging.getLogger("okta_agents")


def make_llm(settings: Settings):
    from langchain_openai import ChatOpenAI

    # NOTE: no temperature — gpt-5-mini rejects non-default temperature.
    return ChatOpenAI(model=settings.model, api_key=settings.openai_api_key,
                      max_retries=3)


def make_retriever(settings: Settings, rebuild: bool = False):
    from langchain_openai import OpenAIEmbeddings

    from okta_agents.knowledge_base import build_vectorstore

    embeddings = OpenAIEmbeddings(model=settings.embedding_model,
                                  api_key=settings.openai_api_key)
    store = build_vectorstore(settings.kb_dir, settings.chroma_dir, embeddings,
                              rebuild=rebuild)
    return store.as_retriever(search_kwargs={"k": 4})


def run_pipeline(
    settings: Settings,
    log_path: str,
    *,
    llm,
    retriever,
    limit_rows: int | None = None,
    max_cases: int | None = None,
    risk_threshold: int | None = None,
) -> list[IncidentTicket]:
    if max_cases is None:
        max_cases = settings.max_cases
    if risk_threshold is None:
        risk_threshold = settings.risk_threshold

    log.info("Loading logs from %s ...", log_path)
    df = load_logs(log_path, limit_rows=limit_rows)
    log.info(
        "%d distinct users across %d user events; computing signals ...",
        df["actor.alternate_id"].nunique(),
        len(df),
    )
    signals = compute_user_signals(df)
    cases = build_cases(df, signals, max_cases, settings.max_events_per_case)
    log.info("%d candidate case(s) selected from %d flagged user(s)",
             len(cases), len(signals))

    run_dir = settings.reports_dir / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    graph = build_graph(llm, retriever)
    tickets: list[IncidentTicket] = []
    for case in cases:
        log.info("=== %s (%s) signals=%s", case.case_id, case.user_email, case.signals)
        try:
            state = graph.invoke(
                {"case": case, "risk_threshold": risk_threshold},
                config={"configurable": {"thread_id": case.case_id}},
            )
            ticket = ticket_from_state(case, state)
        except Exception as exc:  # per-case isolation
            log.exception("case %s failed", case.case_id)
            ticket = error_ticket(case, str(exc))
        tickets.append(ticket)
        # Write each report the moment its case finishes, and refresh the
        # summary, so reports appear one by one instead of all at the end.
        write_ticket(ticket, run_dir)
        write_summary(tickets, run_dir)
        log.info("Wrote report %d/%d: %s (%s) -> %s",
                 len(tickets), len(cases), ticket.case_id, ticket.status, run_dir)

    log.info("Wrote %d report(s) to %s", len(tickets), run_dir)
    return tickets
