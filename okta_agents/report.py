"""Renders IncidentTickets to JSON + Markdown reports."""

from pathlib import Path

from okta_agents.models import CandidateCase, IncidentTicket

# Plain-language phrase per pre-filter signal, for the report's summary line.
_SIGNAL_PHRASES = [
    ("workday_new_device",
     "Quick Workday login right after a new-device notification, with prior failed logins"),
    ("ip_mfa_campaign", "Part of a detected MFA attack campaign from a hosting IP block"),
    ("impossible_travel", "Impossible travel between consecutive logins"),
    ("sensitive_event", "Sensitive admin / privilege / MFA-factor activity"),
    ("rare_country", "Login from a country rare for this user"),
]


_FATIGUE_PHRASE = "Repeated failed logins / MFA prompts (possible MFA fatigue)"


def _issue_phrases(signals: dict) -> list[str]:
    parts = [phrase for key, phrase in _SIGNAL_PHRASES if signals.get(key)]
    if signals.get("failed_auth") or signals.get("mfa_denied"):
        parts.append(_FATIGUE_PHRASE)
    return parts


def signal_headline(signals: dict) -> str:
    """A one-line plain-language summary of the issues the pre-filter found."""
    return "; ".join(_issue_phrases(signals)) or "Flagged for review"


def _person_name(email: str) -> str:
    """'angelle.galeano.ramos@x' -> 'Angelle Galeano Ramos'."""
    return email.split("@")[0].replace(".", " ").replace("-", " ").title()


def ticket_from_state(case: CandidateCase, state: dict) -> IncidentTicket:
    triage = state.get("triage")
    status = "escalated" if triage and triage.decision == "escalate" else "dismissed"
    return IncidentTicket(
        case_id=case.case_id,
        user_email=case.user_email,
        status=status,
        signals=case.signals,
        ingestion=state.get("ingestion"),
        timeline=state.get("timeline"),
        risk=state.get("risk"),
        triage=triage,
        remediation=state.get("remediation"),
    )


def error_ticket(case: CandidateCase, message: str) -> IncidentTicket:
    return IncidentTicket(case_id=case.case_id, user_email=case.user_email,
                          status="error", signals=case.signals, error=message)


def _render_md(t: IncidentTicket) -> str:
    lines = [f"# Incident {t.case_id} — {t.status.upper()}", "",
             f"**User:** {t.user_email}", f"**Pre-filter signals:** {t.signals}", ""]
    if t.error:
        lines += ["## Error", t.error, ""]
    if t.risk:
        lines += ["## Risk Assessment", f"**Summary:** {signal_headline(t.signals)}", "",
                  f"Risk score: {t.risk.risk_score}", "",
                  t.risk.reasoning, ""]
        for p in t.risk.matched_patterns:
            lines.append(f"- **{p.pattern_name}** ({p.confidence}): {'; '.join(p.evidence)}")
        lines += ["", f"KB sources: {', '.join(t.risk.kb_sources)}", ""]
    if t.timeline:
        lines += ["## Timeline", t.timeline.narrative, ""]
        for e in t.timeline.entries:
            lines.append(f"- `{e.timestamp}` [{e.significance}] {e.description}")
        lines += ["", "**Anomalies:**"] + [f"- {a}" for a in t.timeline.anomalies] + [""]
    if t.triage:
        lines += ["## Triage", f"Decision: **{t.triage.decision}**",
                  t.triage.rationale, f"Business impact: {t.triage.business_impact}", ""]
    if t.remediation:
        lines += ["## Remediation Plan (ADVISORY — not executed)",
                  f"Priority: **{t.remediation.priority}** — {t.remediation.summary}", ""]
        for s in sorted(t.remediation.steps, key=lambda s: s.order):
            lines.append(f"{s.order}. **{s.action}** — {s.detail}")
        lines.append("")
    if t.ingestion:
        lines += ["## Ingestion Report", t.ingestion.event_type_summary,
                  f"Range: {t.ingestion.time_range}"]
        lines += [f"- {n}" for n in t.ingestion.data_integrity_notes]
    return "\n".join(lines) + "\n"


def write_reports(tickets: list[IncidentTicket], out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for t in tickets:
        write_ticket(t, out_dir)
    write_summary(tickets, out_dir)


def write_ticket(ticket: IncidentTicket, out_dir: Path) -> None:
    """Write one incident's JSON + Markdown as soon as its case completes."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{ticket.case_id}.json").write_text(ticket.model_dump_json(indent=2))
    (out_dir / f"{ticket.case_id}.md").write_text(_render_md(ticket))


def write_summary(tickets: list[IncidentTicket], out_dir: Path) -> None:
    """(Re)write the run summary index over the tickets completed so far."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = ["# Run Summary", "", "| Case | User | Status | Risk |", "|---|---|---|---|"]
    for t in tickets:
        score = t.risk.risk_score if t.risk else "-"
        rows.append(f"| {t.case_id} | {t.user_email} | {t.status} | {score} |")

    # Aggregate rollup: which issues were found, and in which cases.
    ordered_phrases = [phrase for _, phrase in _SIGNAL_PHRASES] + [_FATIGUE_PHRASE]
    by_issue: dict[str, list[str]] = {p: [] for p in ordered_phrases}
    for t in tickets:
        for phrase in _issue_phrases(t.signals):
            by_issue[phrase].append(_person_name(t.user_email))
    rows += ["", "## Issues found across all cases", ""]
    found_any = False
    for phrase in ordered_phrases:
        cases = by_issue[phrase]
        if not cases:
            continue
        found_any = True
        n = f"{len(cases)} case" + ("s" if len(cases) != 1 else "")
        rows.append(f"- **{phrase}** — {n}: {', '.join(cases)}")
    if not found_any:
        rows.append("- No pre-filter issues recorded.")

    # Raw email list for easy copy/paste (one per line, sorted A-Z).
    rows += ["", "## All flagged email addresses", "", "```"]
    rows += sorted(t.user_email for t in tickets)
    rows += ["```"]
    (out_dir / "summary.md").write_text("\n".join(rows) + "\n")
