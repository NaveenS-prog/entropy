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
    "ALLOW_LOCALHOST_NO_KEY",
    "ENTROPY_ALLOW_LOCALHOST_NO_KEY",
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
    monkeypatch.setattr(settings, "ALLOW_LOCALHOST_NO_KEY", False)

    import shutil
    import tempfile

    from app.persistence.database import scan_db

    temp_root = tempfile.mkdtemp(prefix="entropy_test_scans_")
    test_db_dir = Path(temp_root)
    test_db_path = test_db_dir / "entropy_scans.db"
    monkeypatch.setattr(scan_db, "db_path", test_db_path)
    monkeypatch.setattr(settings, "SCAN_STORAGE_DIR", test_db_dir)
    scan_db._init_db()

    monkeypatch.setattr(
        settings,
        "SCAN_ALLOWED_ROOTS",
        [str(Path.cwd().resolve()), tempfile.gettempdir(), temp_root],
    )

    try:
        yield
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.fixture(autouse=True)
def test_client_auth_override(request: pytest.FixtureRequest):
    """Override verify_api_key dependency for standard test suites unless testing security specifically."""
    from app.api.v1.security import verify_api_key
    from app.main import app

    if "test_api_security" in request.node.nodeid:
        yield
        return

    app.dependency_overrides[verify_api_key] = lambda: True
    try:
        yield
    finally:
        app.dependency_overrides.pop(verify_api_key, None)
