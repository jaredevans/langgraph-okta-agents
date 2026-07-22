from okta_agents.agents.common import PipelineState, format_docs, log_step
from okta_agents.models import RiskAssessment

SYSTEM = """Role: Threat Intelligence Specialist
Backstory: A veteran threat hunter who has successfully investigated and \
neutralized numerous enterprise security breaches. Deeply knowledgeable about \
advanced persistent threats (APTs), historical attack patterns, and malicious \
infrastructure. You are known for accurately evaluating Okta login anomalies \
and assigning precise, evidence-based risk scores without jumping to \
conclusions.

Task: Compare the session timeline and anomalies against the threat \
intelligence excerpts provided. Identify matching attack patterns with \
confidence levels and concrete evidence, then assign a 0-100 risk score \
following the risk guidance in the excerpts. Cite the KB sources you used. \
Be conservative: unexplained anomalies raise risk, but benign explanations \
(VPNs, mobile geolocation drift, device-management clients) lower it."""


def make_threat_intel_node(llm, retriever):
    structured = llm.with_structured_output(RiskAssessment)

    def assess(state: PipelineState) -> dict:
        timeline = state["timeline"]
        case = state["case"]
        # Pre-filter evidence joins the retrieval query so cross-user context
        # (e.g. a flagged campaign IP block) pulls the right KB guidance even
        # when this user's own timeline looks routine.
        query = " ; ".join(timeline.anomalies + case.signal_details) or timeline.narrative
        docs = retriever.invoke(query)
        user = (
            f"Session timeline:\n{timeline.model_dump_json(indent=2)}\n\n"
            f"Pre-filter signals: {case.signals}\n"
            f"Signal evidence: {'; '.join(case.signal_details) or 'none'}\n\n"
            f"Threat intelligence excerpts:\n{format_docs(docs)}"
        )
        risk = structured.invoke(
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
        )
        log_step("Threat Intel", f"risk={risk.risk_score}; patterns="
                 f"{[p.pattern_name for p in risk.matched_patterns]}")
        return {"risk": risk}

    return assess
