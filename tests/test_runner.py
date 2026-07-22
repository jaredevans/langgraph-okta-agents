from langchain_core.runnables import RunnableLambda

from okta_agents.config import Settings
from okta_agents.runner import run_pipeline
from tests.fakes import fake_retriever
from tests.test_graph import _llm


def _settings(tmp_path):
    return Settings(openai_api_key="sk-test", reports_dir=tmp_path / "reports")


def test_run_pipeline_end_to_end_with_fakes(tmp_path, log_csv):
    rows = [
        {"actor.alternate_id": "victim@example.edu",
         "timestamp": f"2026-07-21T01:{i:02d}:00.000Z",
         "event_type": "user.session.start", "outcome.result": "FAILURE"}
        for i in range(8)
    ]
    tickets = run_pipeline(
        _settings(tmp_path), log_csv(rows), llm=_llm("escalate"),
        retriever=fake_retriever(),
    )
    assert len(tickets) == 1
    assert tickets[0].status == "escalated"
    assert tickets[0].user_email == "victim@example.edu"
    out = tmp_path / "reports"
    run_dirs = list(out.iterdir())
    assert len(run_dirs) == 1
    assert (run_dirs[0] / "summary.md").exists()


def test_run_pipeline_respects_explicit_zero_max_cases(tmp_path, log_csv):
    rows = [
        {"actor.alternate_id": "victim@example.edu",
         "timestamp": f"2026-07-21T01:{i:02d}:00.000Z",
         "event_type": "user.session.start", "outcome.result": "FAILURE"}
        for i in range(8)
    ]
    tickets = run_pipeline(
        _settings(tmp_path), log_csv(rows), llm=_llm("escalate"),
        retriever=fake_retriever(), max_cases=0,
    )
    assert tickets == []


def test_run_pipeline_isolates_case_failures(tmp_path, log_csv):
    rows = [
        {"actor.alternate_id": "victim@example.edu",
         "timestamp": f"2026-07-21T01:{i:02d}:00.000Z",
         "event_type": "user.session.start", "outcome.result": "FAILURE"}
        for i in range(8)
    ]

    class ExplodingLLM:
        def with_structured_output(self, schema):
            def _raise(_input):
                raise RuntimeError("api down")

            return RunnableLambda(_raise)

    tickets = run_pipeline(
        _settings(tmp_path), log_csv(rows), llm=ExplodingLLM(),
        retriever=fake_retriever(),
    )
    assert len(tickets) == 1
    assert tickets[0].status == "error"
    assert "api down" in tickets[0].error


def test_run_pipeline_logs_distinct_user_count(tmp_path, log_csv, caplog):
    import logging

    caplog.set_level(logging.INFO, logger="okta_agents")
    rows = [
        {"actor.alternate_id": "a@example.edu",
         "timestamp": "2026-07-21T01:00:00.000Z",
         "event_type": "user.session.start", "outcome.result": "FAILURE"},
        {"actor.alternate_id": "b@example.edu",
         "timestamp": "2026-07-21T01:01:00.000Z",
         "event_type": "user.session.start", "outcome.result": "SUCCESS"},
    ]
    run_pipeline(
        _settings(tmp_path), log_csv(rows), llm=_llm("dismiss"),
        retriever=fake_retriever(),
    )
    assert any("2 distinct users" in m for m in caplog.messages)
