import pandas as pd
import pytest

COLUMNS_DEFAULTS = {
    "severity": "INFO",
    "event_type": "user.authentication.sso",
    "display_message": "User single sign on to app",
    "timestamp": "2026-07-21T10:00:00.000Z",
    "outcome.result": "SUCCESS",
    "actor.type": "User",
    "actor.display_name": "Test User",
    "actor.alternate_id": "test.user@example.edu",
    "client.ip_address": "10.0.0.1",
    "client.geographical_context.country": "United States",
    "client.geographical_context.city": "Washington",
    "client.geographical_context.geolocation.lat": "38.9034",
    "client.geographical_context.geolocation.lon": "-76.9882",
    "client.user_agent.raw_user_agent": "Mozilla/5.0",
    "target0.display_name": "",
}


def make_log_df(rows: list[dict]) -> pd.DataFrame:
    """Each row dict overrides COLUMNS_DEFAULTS; missing columns get defaults."""
    return pd.DataFrame([{**COLUMNS_DEFAULTS, **row} for row in rows])


@pytest.fixture
def log_csv(tmp_path):
    """Write a list of row-override dicts to a CSV file and return its path."""

    def _write(rows: list[dict]) -> str:
        path = tmp_path / "logs.csv"
        make_log_df(rows).to_csv(path, index=False)
        return str(path)

    return _write
