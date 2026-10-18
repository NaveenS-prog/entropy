from pathlib import Path

import pytest

from app.core.config import settings

ENV_VARS_TO_CLEAR = [
    "GITHUB_TOKEN",
    "ENTROPY_GITHUB_TOKEN",
    "GITHUB_APP_ID",
    "ENTROPY_GITHUB_APP_ID",
    "GITHUB_PRIVATE_KEY",
    "ENTROPY_GITHUB_PRIVATE_KEY",
    "GITHUB_WEBHOOK_SECRET",
    "ENTROPY_GITHUB_WEBHOOK_SECRET",
    "AI_API_KEY",
    "ENTROPY_AI_API_KEY",
    "GEMINI_API_KEY",
    "API_KEY",
    "ENTROPY_API_KEY",
    "SCAN_ALLOWED_ROOTS",
    "ENTROPY_SCAN_ALLOWED_ROOTS",
]


@pytest.fixture(autouse=True)
def hermetic_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no ambient environment variables contaminate tests."""
    for var in ENV_VARS_TO_CLEAR:
        monkeypatch.delenv(var, raising=False)

    # Reset any cached settings attributes that might have been populated from ambient env
    monkeypatch.setattr(settings, "GITHUB_TOKEN", None)
    monkeypatch.setattr(settings, "GITHUB_APP_ID", None)
    monkeypatch.setattr(settings, "GITHUB_PRIVATE_KEY", None)
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)
    monkeypatch.setattr(settings, "AI_API_KEY", None)
    monkeypatch.setattr(settings, "API_KEY", None)

    import tempfile
    monkeypatch.setattr(
        settings,
        "SCAN_ALLOWED_ROOTS",
        [str(Path.cwd().resolve()), tempfile.gettempdir()],
    )
