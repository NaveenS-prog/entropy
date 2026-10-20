"""Integration tests for API key enforcement, localhost restriction, allowed roots boundary, and path privacy."""

import hmac
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.main import app

# Simulate localhost caller (127.0.0.1 is in LOCALHOST_HOSTS)
client = TestClient(app, client=("127.0.0.1", 50000))


def test_health_route_accessible_without_api_key(monkeypatch: pytest.MonkeyPatch):
    """Health route is always public and exempt from API key."""
    monkeypatch.setattr(settings, "API_KEY", "super_secret_key_123")
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_api_key_required_when_configured_missing_key(monkeypatch: pytest.MonkeyPatch):
    """When API_KEY is configured, requests without X-API-Key header receive 401."""
    monkeypatch.setattr(settings, "API_KEY", "super_secret_key_123")
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 401
    assert "Invalid or missing API key" in resp.json()["detail"]


def test_api_key_required_when_configured_wrong_key(monkeypatch: pytest.MonkeyPatch):
    """When API_KEY is configured, requests with invalid X-API-Key receive 401."""
    monkeypatch.setattr(settings, "API_KEY", "super_secret_key_123")
    resp = client.get("/api/v1/scans", headers={"X-API-Key": "incorrect_key"})
    assert resp.status_code == 401
    assert "Invalid or missing API key" in resp.json()["detail"]


def test_api_key_valid_allows_access(monkeypatch: pytest.MonkeyPatch):
    """When API_KEY is configured, valid X-API-Key header grants access."""
    monkeypatch.setattr(settings, "API_KEY", "super_secret_key_123")
    resp = client.get("/api/v1/scans", headers={"X-API-Key": "super_secret_key_123"})
    assert resp.status_code == 200


def test_compare_digest_used_for_api_key_verification(monkeypatch: pytest.MonkeyPatch):
    """API key verification must use hmac.compare_digest for constant-time comparison."""
    monkeypatch.setattr(settings, "API_KEY", "super_secret_key_123")
    with patch("app.api.v1.security.hmac.compare_digest", wraps=hmac.compare_digest) as mock_cmp:
        resp = client.get("/api/v1/scans", headers={"X-API-Key": "super_secret_key_123"})
        assert resp.status_code == 200
        assert mock_cmp.called


def test_no_key_and_localhost_no_key_disabled_returns_401(monkeypatch: pytest.MonkeyPatch):
    """When no API key is configured and ALLOW_LOCALHOST_NO_KEY is False, even localhost receives 401."""
    monkeypatch.setattr(settings, "API_KEY", None)
    monkeypatch.setattr(settings, "ALLOW_LOCALHOST_NO_KEY", False)
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 401
    assert "localhost fallback is disabled" in resp.json()["detail"]


def test_no_key_and_localhost_no_key_enabled_allows_localhost(monkeypatch: pytest.MonkeyPatch):
    """When no API key is configured and ALLOW_LOCALHOST_NO_KEY is True, localhost access is permitted."""
    monkeypatch.setattr(settings, "API_KEY", None)
    monkeypatch.setattr(settings, "ALLOW_LOCALHOST_NO_KEY", True)
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200


def test_non_localhost_rejected_when_no_key_configured(monkeypatch: pytest.MonkeyPatch):
    """When no API key is configured, non-localhost callers receive 401."""
    monkeypatch.setattr(settings, "API_KEY", None)
    monkeypatch.setattr(settings, "ALLOW_LOCALHOST_NO_KEY", True)
    remote_client = TestClient(app, client=("192.168.1.100", 54321))
    resp = remote_client.get("/api/v1/scans")
    assert resp.status_code == 401
    assert "Non-localhost access requires ENTROPY_API_KEY" in resp.json()["detail"]


def test_allow_public_access_allows_remote_client_without_key(monkeypatch: pytest.MonkeyPatch):
    """When ALLOW_PUBLIC_ACCESS is True and no API_KEY configured, remote callers are allowed."""
    monkeypatch.setattr(settings, "API_KEY", None)
    monkeypatch.setattr(settings, "ALLOW_PUBLIC_ACCESS", True)
    remote_client = TestClient(app, client=("192.168.1.100", 54321))
    resp = remote_client.get("/api/v1/scans")
    assert resp.status_code == 200


def test_testclient_host_removed_from_localhost_hosts(monkeypatch: pytest.MonkeyPatch):
    """The 'testclient' pseudo-host is no longer in LOCALHOST_HOSTS and must receive 401 in production."""
    monkeypatch.setattr(settings, "API_KEY", None)
    monkeypatch.setattr(settings, "ALLOW_LOCALHOST_NO_KEY", True)
    unmocked_client = TestClient(app)  # defaults client host to "testclient"
    resp = unmocked_client.get("/api/v1/scans")
    assert resp.status_code == 401
    assert "Non-localhost access requires ENTROPY_API_KEY" in resp.json()["detail"]


def test_scan_path_outside_allowed_roots_rejected_with_400(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """LocalRepositorySource must reject any path whose resolved location is outside SCAN_ALLOWED_ROOTS with 400 SECURITY_VIOLATION."""
    allowed_dir = tmp_path / "allowed_workspace"
    allowed_dir.mkdir()
    outside_dir = tmp_path / "outside_workspace"
    outside_dir.mkdir()

    monkeypatch.setattr(settings, "SCAN_ALLOWED_ROOTS", [str(allowed_dir)])
    monkeypatch.setattr(settings, "API_KEY", None)
    monkeypatch.setattr(settings, "ALLOW_LOCALHOST_NO_KEY", True)

    # Post scan pointing to outside directory
    resp = client.post(
        "/api/v1/scans",
        json={"path": str(outside_dir), "repo_name": "outside_repo"},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "SECURITY_VIOLATION"
    # Ensure error detail strictly masks internal server paths and allowed roots
    assert data["detail"] == "path is outside the allowed scan roots"
    assert str(outside_dir) not in resp.text
    assert str(allowed_dir) not in resp.text


def test_unauthenticated_caller_does_not_receive_absolute_server_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """List and summary responses must redact absolute server filesystem paths unless authenticated."""
    scan_dir = tmp_path / "test_repo"
    scan_dir.mkdir()
    (scan_dir / "app.py").write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr(settings, "SCAN_ALLOWED_ROOTS", [str(tmp_path)])
    monkeypatch.setattr(settings, "API_KEY", "secure_admin_key_777")
    monkeypatch.setattr(settings, "ALLOW_LOCALHOST_NO_KEY", True)

    # Ingest scan as authenticated caller
    create_resp = client.post(
        "/api/v1/scans",
        json={"path": str(scan_dir), "repo_name": "test_repo"},
        headers={"X-API-Key": "secure_admin_key_777"},
    )
    assert create_resp.status_code == 201

    # 1. Unauthenticated request (or localhost with no key configured): absolute path must NOT be exposed
    monkeypatch.setattr(settings, "API_KEY", None)
    unauth_resp = client.get("/api/v1/scans")
    assert unauth_resp.status_code == 200
    scans_unauth = unauth_resp.json()
    assert len(scans_unauth) >= 1
    # Check that repo_path is redacted to repo_name, not the full absolute path
    matched = [s for s in scans_unauth if s["repo_name"] == "test_repo"]
    assert matched
    assert matched[0]["repo_path"] == "test_repo"
    assert str(scan_dir) not in matched[0]["repo_path"]

    # 2. Authenticated request with key: full path IS exposed
    monkeypatch.setattr(settings, "API_KEY", "secure_admin_key_777")
    auth_resp = client.get("/api/v1/scans", headers={"X-API-Key": "secure_admin_key_777"})
    assert auth_resp.status_code == 200
    scans_auth = auth_resp.json()
    matched_auth = [s for s in scans_auth if s["repo_name"] == "test_repo"]
    assert matched_auth
    assert matched_auth[0]["repo_path"] == str(scan_dir.resolve())


def test_scan_allowed_roots_parsing_formats():
    """Verify that plain path, comma-separated paths, and JSON array strings parse correctly, while malformed raises clean ValidationError."""
    # 1. Plain string path
    s1 = Settings(SCAN_ALLOWED_ROOTS="/workspace/single")
    assert s1.SCAN_ALLOWED_ROOTS == ["/workspace/single"]

    # 2. Comma-separated paths
    s2 = Settings(SCAN_ALLOWED_ROOTS="/workspace/a, /workspace/b")
    assert s2.SCAN_ALLOWED_ROOTS == ["/workspace/a", "/workspace/b"]

    # 3. JSON array
    s3 = Settings(SCAN_ALLOWED_ROOTS='["/workspace/json1", "/workspace/json2"]')
    assert s3.SCAN_ALLOWED_ROOTS == ["/workspace/json1", "/workspace/json2"]

    # 4. Malformed value produces clean ValidationError
    with pytest.raises(ValidationError) as exc_info:
        Settings(SCAN_ALLOWED_ROOTS="[invalid-json")
    err_str = str(exc_info.value)
    assert "Invalid JSON array for allowed roots" in err_str
