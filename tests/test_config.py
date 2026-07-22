import pytest
from okta_agents.config import Settings, load_settings


def test_load_settings_reads_key_from_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("OPENAI_API_KEY=sk-test-123\n")
    settings = load_settings(str(env))
    assert settings.openai_api_key == "sk-test-123"
    assert settings.model == "gpt-5-mini"
    assert settings.risk_threshold == 70
    assert settings.max_cases == 5
    assert settings.max_events_per_case == 75


def test_env_file_overrides_stale_shell_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-stale-from-shell")
    env = tmp_path / ".env"
    env.write_text("OPENAI_API_KEY=sk-from-env-file\n")
    settings = load_settings(str(env))
    assert settings.openai_api_key == "sk-from-env-file"


def test_load_settings_raises_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("")
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        load_settings(str(env))
