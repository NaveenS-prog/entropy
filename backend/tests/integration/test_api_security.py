"""Integration tests for API key enforcement, localhost restriction, allowed roots boundary, and path privacy."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)


def test_health_route_accessible_without_api_key(monkeypatch: pytest.MonkeyPatch):
    """Health route is always public and exempt from API key."""
    monkeypatch.setattr(settings, "API_KEY", "super_secret_key_123")
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_api_key_required_when_configured_no_key(monkeypatch: pytest.MonkeyPatch):
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


def test_non_localhost_rejected_when_no_key_configured(monkeypatch: pytest.MonkeyPatch):
    """When no API key is configured, non-localhost callers receive 401."""
    monkeypatch.setattr(settings, "API_KEY", None)
    remote_client = TestClient(app, client=("192.168.1.100", 54321))
    resp = remote_client.get("/api/v1/scans")
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

    # Post scan pointing to outside directory
    resp = client.post(
        "/api/v1/scans",
        json={"path": str(outside_dir), "repo_name": "outside_repo"},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["error_code"] == "SECURITY_VIOLATION"
    assert "not inside allowed roots" in data["detail"]


def test_unauthenticated_caller_does_not_receive_absolute_server_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """List and summary responses must redact absolute server filesystem paths unless authenticated."""
    scan_dir = tmp_path / "test_repo"
    scan_dir.mkdir()
    (scan_dir / "app.py").write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr(settings, "SCAN_ALLOWED_ROOTS", [str(tmp_path)])
    monkeypatch.setattr(settings, "API_KEY", "secure_admin_key_777")

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
