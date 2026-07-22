import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Settings:
    openai_api_key: str
    model: str = "gpt-5-mini"
    embedding_model: str = "text-embedding-3-small"
    risk_threshold: int = 70
    max_cases: int = 5
    max_events_per_case: int = 75
    kb_dir: Path = field(default_factory=lambda: Path("kb"))
    chroma_dir: Path = field(default_factory=lambda: Path("chroma_db"))
    reports_dir: Path = field(default_factory=lambda: Path("reports"))


def load_settings(env_file: str | None = ".env") -> Settings:
    if env_file:
        # override=True: the project .env is the source of truth for the key,
        # beating any stale OPENAI_API_KEY already exported in the shell.
        load_dotenv(env_file, override=True)
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        raise RuntimeError(
            "OPENAI_API_KEY not set. Copy .env.example to .env and add your key."
        )
    return Settings(openai_api_key=key)
