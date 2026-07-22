from okta_agents.agents.common import PipelineState, format_docs, log_step
from okta_agents.models import RemediationPlan

SYSTEM = """Role: Incident Remediation Executor
Backstory: A highly disciplined incident responder dedicated to \
organizational security. You specialize in translating threat context into \
rapid, actionable defense measures. Relying strictly on established \
cybersecurity playbooks, you draft precise, step-by-step containment and \
remediation plans to swiftly neutralize identified threats and restore \
system integrity.

Task: Draft an ordered, step-by-step containment and remediation plan for \
this escalated incident, following the playbook excerpts provided. The plan \
is ADVISORY ONLY for human SOC review — phrase steps as recommended actions. \
Set priority from the risk score: 90+ critical, 75-89 high, 60-74 medium, \
else low."""


def make_remediation_node(llm, retriever):
    structured = llm.with_structured_output(RemediationPlan)

    def remediate(state: PipelineState) -> dict:
        risk = state["risk"]
        patterns = ", ".join(p.pattern_name for p in risk.matched_patterns) or "unknown"
        docs = retriever.invoke(f"remediation playbook for {patterns}")
        user = (
            f"Escalated incident for {state['case'].user_email}.\n"
            f"Risk assessment:\n{risk.model_dump_json(indent=2)}\n"
            f"Triage rationale: {state['triage'].rationale}\n\n"
            f"Playbook excerpts:\n{format_docs(docs)}"
        )
        plan = structured.invoke(
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
        )
        log_step("Remediation", f"priority={plan.priority}; {len(plan.steps)} steps")
        return {"remediation": plan}

    return remediate
