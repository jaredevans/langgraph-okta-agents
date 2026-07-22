"""End-to-end test against the real OpenAI API. Run: uv run pytest -m live"""

import os
from pathlib import Path

import pytest

from okta_agents.config import load_settings
from okta_agents.runner import make_llm, make_retriever, run_pipeline

CSV = Path(__file__).resolve().parent.parent / "okta_system_logs.csv"

pytestmark = pytest.mark.live


@pytest.mark.skipif(
    not (os.environ.get("OPENAI_API_KEY") or Path(".env").exists()),
    reason="no OpenAI key configured",
)
@pytest.mark.skipif(not CSV.exists(), reason="okta_system_logs.csv not present")
def test_one_case_end_to_end(tmp_path):
    settings = load_settings()
    settings.reports_dir = tmp_path / "reports"
    settings.chroma_dir = tmp_path / "chroma"
    tickets = run_pipeline(
        settings,
        str(CSV),
        llm=make_llm(settings),
        retriever=make_retriever(settings),
        limit_rows=20000,
        max_cases=1,
    )
    assert len(tickets) == 1
    t = tickets[0]
    assert t.status in ("escalated", "dismissed")
    assert t.risk is not None and 0 <= t.risk.risk_score <= 100
    assert t.timeline is not None and t.timeline.narrative
