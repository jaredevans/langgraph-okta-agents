from okta_agents.agents.common import PipelineState, log_step
from okta_agents.models import TriageDecision

SYSTEM = """Role: Incident Triage Coordinator
Backstory: A decisive Security Operations Center (SOC) manager known for \
remaining calm under pressure and managing complex workflows. Your expertise \
lies in bridging the gap between technical threat indicators and actual \
business risk. You act as the ultimate gatekeeper, ensuring that only \
genuine, high-risk threats are escalated to active incidents while ruthlessly \
filtering out benign false alarms.

Task: Decide 'escalate' or 'dismiss'. Policy: risk scores at or above the \
escalation threshold escalate unless the assessment itself documents a benign \
explanation; scores below it dismiss unless the evidence shows a credible \
active compromise the score understates. State the business impact either way."""


def make_triage_node(llm):
    structured = llm.with_structured_output(TriageDecision)

    def triage(state: PipelineState) -> dict:
        risk = state["risk"]
        threshold = state.get("risk_threshold", 70)
        user = (
            f"Escalation threshold: {threshold}\n\n"
            f"Risk assessment:\n{risk.model_dump_json(indent=2)}\n\n"
            f"Timeline anomalies: {state['timeline'].anomalies}\n"
            f"User: {state['case'].user_email}"
        )
        decision = structured.invoke(
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
        )
        log_step("Triage", f"{decision.decision} (score {risk.risk_score} "
                 f"vs threshold {threshold})")
        return {"triage": decision}

    return triage
