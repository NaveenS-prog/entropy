"""Integration tests for Phase 7 AI Explanation & Remediation Layer."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.ai.cache import AIExplanationCache
from app.ai.provider import FakeAIProvider
from app.ai.service import ai_service
from app.core.config import settings
from app.main import app

client = TestClient(app)


def test_phase7_full_lifecycle(tmp_path: Path):
    """Verify complete Phase 7 lifecycle:
    1. Scan a repository with deterministic findings.
    2. Confirm deterministic score and findings are intact.
    3. Request AI explanation when AI_ENABLED is False -> verify 400 rejection.
    4. Enable AI and request explanation -> verify 200 with structured schema.
    5. Verify deterministic finding and scores are 100% UNCHANGED before and after AI call.
    6. Request explanation a second time -> verify cache is hit and provider is not called again.
    7. Verify provider error handling when provider fails or returns malformed response.
    8. Verify 404 on invalid finding ID.
    """
    repo_dir = tmp_path / "phase7_test_repo"
    repo_dir.mkdir()

    # Create code with deliberate debt: broad exception handler (ENT-ERR-002)
    sample_code = (
        "def calculate_total(items):\n"
        "    try:\n"
        "        return sum(items)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    (repo_dir / "calculator.py").write_text(sample_code, encoding="utf-8")

    # 1. Trigger scan
    scan_resp = client.post(
        "/api/v1/repositories/scan",
        json={"path": str(repo_dir), "repo_name": "phase7_repo"},
    )
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["scan_id"]

    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1

    score_resp = client.get(f"/api/v1/scans/{scan_id}/score")
    assert score_resp.status_code == 200
    initial_score = score_resp.json()["total_score"]

    target_finding = findings[0]
    finding_id = target_finding["id"]
    initial_severity = target_finding["severity"]
    initial_confidence = target_finding["confidence"]
    initial_fingerprint = target_finding["fingerprint"]

    # 2. Test AI disabled mode (default or forced)
    settings.AI_ENABLED = False
    disabled_resp = client.post(f"/api/v1/findings/{finding_id}/explanation")
    assert disabled_resp.status_code == 400
    assert "disabled" in disabled_resp.json()["detail"].lower()

    # Also test via scan-scoped endpoint
    disabled_resp_scoped = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/explanation"
    )
    assert disabled_resp_scoped.status_code == 400

    # 3. Setup Fake AI Provider with controlled cache
    fake_provider = FakeAIProvider(model_name="mock-gemini-explainer")
    test_cache = AIExplanationCache(cache_dir=tmp_path / "test_ai_cache")
    ai_service.cache = test_cache
    ai_service.set_provider(fake_provider)
    settings.AI_ENABLED = True

    # 4. Request AI explanation successfully
    resp = client.post(f"/api/v1/findings/{finding_id}/explanation")
    assert resp.status_code == 200, resp.text
    explanation = resp.json()

    assert explanation["finding_id"] == finding_id
    assert explanation["model"] == "mock-gemini-explainer"
    assert "calculator.py" in explanation["summary"] or "ENT-ERR-002" in explanation["summary"]
    assert "why_it_matters" in explanation
    assert "evidence_explanation" in explanation
    assert "architectural_impact" in explanation
    assert "remediation" in explanation
    assert "suggested_pattern" in explanation
    assert explanation["confidence"] in ["low", "medium", "high"]
    assert "advisory only" in explanation["disclaimer"].lower()
    assert fake_provider.call_count == 1

    # 5. Invariant check: deterministic findings & score remain completely unchanged
    post_scan_resp = client.get(f"/api/v1/scans/{scan_id}")
    assert post_scan_resp.status_code == 200
    post_scan_data = post_scan_resp.json()
    assert post_scan_data["score"]["total_score"] == initial_score

    finding_resp = client.get(f"/api/v1/scans/{scan_id}/findings/{finding_id}")
    assert finding_resp.status_code == 200
    fresh_finding = finding_resp.json()
    assert fresh_finding["severity"] == initial_severity
    assert fresh_finding["confidence"] == initial_confidence
    assert fresh_finding["fingerprint"] == initial_fingerprint

    # 6. Verify caching on repeated request (call_count should remain 1)
    repeat_resp = client.post(f"/api/v1/findings/{finding_id}/explanation")
    assert repeat_resp.status_code == 200
    assert fake_provider.call_count == 1  # Served from cache!

    repeat_scoped_resp = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/explanation"
    )
    assert repeat_scoped_resp.status_code == 200
    assert fake_provider.call_count == 1  # Also served from cache!

    # 7. Test provider error handling
    failing_provider = FakeAIProvider(simulate_error=True)
    ai_service.set_provider(failing_provider)
    test_cache.clear()  # Clear cache to force provider call

    err_resp = client.post(f"/api/v1/findings/{finding_id}/explanation")
    assert err_resp.status_code == 503
    assert "unavailable" in err_resp.json()["detail"].lower()

    # 8. Test malformed response handling
    malformed_provider = FakeAIProvider(simulate_malformed=True)
    ai_service.set_provider(malformed_provider)
    test_cache.clear()

    malformed_resp = client.post(f"/api/v1/findings/{finding_id}/explanation")
    assert malformed_resp.status_code == 503

    # 9. Test 404 for non-existent finding
    missing_resp = client.post("/api/v1/findings/non-existent-finding-id/explanation")
    assert missing_resp.status_code == 404
    assert "not found" in missing_resp.json()["detail"].lower()

    # Reset AI settings to clean state
    settings.AI_ENABLED = False
    ai_service.set_provider(None)

