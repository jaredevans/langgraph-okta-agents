from okta_agents.models import IncidentTicket, TriageDecision
from okta_agents.report import (
    error_ticket,
    ticket_from_state,
    write_reports,
    write_summary,
    write_ticket,
)
from tests.test_agent_nodes import INGESTION, PLAN, RISK, TIMELINE, make_case

ESCALATE = TriageDecision(decision="escalate", rationale="r", business_impact="b")


def _state():
    return {"ingestion": INGESTION, "timeline": TIMELINE, "risk": RISK,
            "triage": ESCALATE, "remediation": PLAN}


def test_ticket_from_state_escalated():
    ticket = ticket_from_state(make_case(), _state())
    assert ticket.status == "escalated"
    assert ticket.risk.risk_score == 85
    assert ticket.remediation == PLAN


def test_ticket_from_state_dismissed():
    state = _state()
    state["triage"] = TriageDecision(decision="dismiss", rationale="benign",
                                     business_impact="none")
    del state["remediation"]
    ticket = ticket_from_state(make_case(), state)
    assert ticket.status == "dismissed"
    assert ticket.remediation is None


def test_error_ticket():
    ticket = error_ticket(make_case(), "boom")
    assert ticket.status == "error"
    assert ticket.error == "boom"


def test_risk_summary_headline_from_signals():
    from okta_agents.report import signal_headline
    assert "campaign" in signal_headline({"ip_mfa_campaign": 4.0}).lower()
    assert "workday" in signal_headline({"workday_new_device": 1.0}).lower()
    assert "travel" in signal_headline({"impossible_travel": 3.0}).lower()
    combo = signal_headline({"workday_new_device": 1.0, "failed_auth": 6.0, "mfa_denied": 6.0})
    assert "workday" in combo.lower() and ";" in combo  # multiple issues joined


def test_risk_assessment_section_leads_with_summary(tmp_path):
    ticket = ticket_from_state(make_case(), _state())  # has ip_mfa? make_case signals: failed_auth
    write_ticket(ticket, tmp_path)
    md = (tmp_path / "case-001-test.md").read_text()
    risk_body = md.split("## Risk Assessment", 1)[1]
    first_line = risk_body.strip().splitlines()[0]
    assert first_line.startswith("**Summary:**")  # headline precedes the score/detail


def test_write_ticket_writes_one_case(tmp_path):
    write_ticket(ticket_from_state(make_case(), _state()), tmp_path)
    assert (tmp_path / "case-001-test.json").exists()
    assert "Risk score: 85" in (tmp_path / "case-001-test.md").read_text()
    assert not (tmp_path / "summary.md").exists()  # summary is written separately


def test_write_summary_reflects_only_completed_tickets(tmp_path):
    write_summary([ticket_from_state(make_case(), _state())], tmp_path)
    summary = (tmp_path / "summary.md").read_text()
    assert "case-001-test" in summary
    assert "case-002" not in summary  # only what's done so far


def test_summary_aggregates_issues_across_cases(tmp_path):
    camp = make_case(case_id="case-001-alice-smith", user_email="alice.smith@x.edu",
                     signals={"ip_mfa_campaign": 4.0})
    both = make_case(case_id="case-002-bob-jones", user_email="bob.jones@x.edu",
                     signals={"ip_mfa_campaign": 2.0, "impossible_travel": 3.0})
    write_summary([ticket_from_state(camp, _state()), ticket_from_state(both, _state())],
                  tmp_path)
    summary = (tmp_path / "summary.md").read_text()
    assert "Issues found across all cases" in summary
    # affected people listed by name, not case id; campaign in both, travel in one
    camp_line = next(l for l in summary.splitlines() if "attack campaign" in l)
    assert "2 case" in camp_line and "Alice Smith" in camp_line and "Bob Jones" in camp_line
    assert "case-001" not in camp_line  # names, not case ids
    travel_line = next(l for l in summary.splitlines() if "Impossible travel" in l)
    assert "1 case" in travel_line and "Bob Jones" in travel_line


def test_summary_ends_with_raw_email_list(tmp_path):
    t1 = ticket_from_state(make_case(case_id="case-001-a", user_email="a@x.edu"), _state())
    t2 = ticket_from_state(make_case(case_id="case-002-b", user_email="b@x.edu"), _state())
    write_summary([t1, t2], tmp_path)
    lines = (tmp_path / "summary.md").read_text().splitlines()
    assert "## All flagged email addresses" in lines
    # a plain code block of one email per line, sorted A-Z, at the very bottom
    body = "\n".join(lines)
    assert "```\na@x.edu\nb@x.edu\n```" in body


def test_summary_email_list_sorted_alphabetically(tmp_path):
    t1 = ticket_from_state(make_case(case_id="case-001-z", user_email="zoe@x.edu"), _state())
    t2 = ticket_from_state(make_case(case_id="case-002-a", user_email="amy@x.edu"), _state())
    write_summary([t1, t2], tmp_path)  # case order is z then a
    body = (tmp_path / "summary.md").read_text()
    assert "```\namy@x.edu\nzoe@x.edu\n```" in body  # emails sorted A-Z regardless


def test_write_reports_creates_files(tmp_path):
    tickets = [
        ticket_from_state(make_case(), _state()),
        error_ticket(make_case(case_id="case-002-test"), "x"),
    ]
    write_reports(tickets, tmp_path)
    json_path = tmp_path / "case-001-test.json"
    md_path = tmp_path / "case-001-test.md"
    summary = tmp_path / "summary.md"
    assert json_path.exists() and md_path.exists() and summary.exists()
    restored = IncidentTicket.model_validate_json(json_path.read_text())
    assert restored.status == "escalated"
    md = md_path.read_text()
    assert "Risk score: 85" in md
    assert "Suspend user" in md
    assert "ADVISORY — not executed" in md
    assert (tmp_path / "case-002-test.json").exists()
    assert (tmp_path / "case-002-test.md").exists()
    summary_text = summary.read_text()
    assert "case-001-test" in summary_text
    assert "case-002-test" in summary_text
    assert "escalated" in summary_text
