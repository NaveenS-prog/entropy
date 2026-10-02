"""Unit tests for Phase 12 GitHub Webhook signature verification and event routing."""

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)
TEST_SECRET = "test_webhook_secret_key_98765"


def _generate_signature(payload_bytes: bytes, secret: str = TEST_SECRET) -> str:
    mac = hmac.new(key=secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def test_webhook_missing_signature():
    """Webhook must be rejected with 401 when signature header is missing."""
    settings.GITHUB_WEBHOOK_SECRET = TEST_SECRET
    response = client.post(
        "/api/v1/webhooks/github",
        content=b'{"action": "opened"}',
        headers={"Content-Type": "application/json", "X-GitHub-Event": "pull_request"},
    )
    assert response.status_code == 401
    assert "Invalid or missing" in response.json()["detail"]


def test_webhook_invalid_signature():
    """Webhook must be rejected with 401 when HMAC signature is invalid."""
    settings.GITHUB_WEBHOOK_SECRET = TEST_SECRET
    response = client.post(
        "/api/v1/webhooks/github",
        content=b'{"action": "opened"}',
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "X-GitHub-Event": "pull_request",
        },
    )
    assert response.status_code == 401


def test_webhook_ping_event():
    """Valid signature ping event returns 200 with pong message."""
    settings.GITHUB_WEBHOOK_SECRET = TEST_SECRET
    payload = json.dumps({"zen": "Keep it logically awesome."}).encode("utf-8")
    sig = _generate_signature(payload)

    response = client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "ping",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "pong"


def test_webhook_malformed_json():
    """Valid signature with malformed JSON body returns 400 Bad Request."""
    settings.GITHUB_WEBHOOK_SECRET = TEST_SECRET
    payload = b"{not-valid-json"
    sig = _generate_signature(payload)

    response = client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        },
    )
    assert response.status_code == 400
    assert "Malformed JSON" in response.json()["detail"]


def test_webhook_unsupported_event():
    """Valid signature with unsupported event is safely ignored."""
    settings.GITHUB_WEBHOOK_SECRET = TEST_SECRET
    payload = json.dumps({"action": "created"}).encode("utf-8")
    sig = _generate_signature(payload)

    response = client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "star",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert response.json()["event"] == "star"


def test_webhook_pull_request_ignored_action():
    """Pull request events with ignored actions (e.g. labeled) return 200 ignored."""
    settings.GITHUB_WEBHOOK_SECRET = TEST_SECRET
    payload = json.dumps({"action": "labeled"}).encode("utf-8")
    sig = _generate_signature(payload)

    response = client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_webhook_missing_required_pr_fields():
    """Pull request opened with missing required fields raises 422 Unprocessable Entity."""
    settings.GITHUB_WEBHOOK_SECRET = TEST_SECRET
    payload = json.dumps({"action": "opened", "pull_request": {}}).encode("utf-8")
    sig = _generate_signature(payload)

    response = client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        },
    )
    assert response.status_code == 422
