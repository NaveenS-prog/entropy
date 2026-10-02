"""Integration tests for Phase 13 Policy API endpoints."""

from fastapi.testclient import TestClient

from app.main import app
from app.models.domain.scan import RepositoryScanResult
from app.persistence.database import scan_db
from app.scoring.models import DebtScoreResult, DebtScoreTier

client = TestClient(app)


def test_get_policies():
    """GET /api/v1/policies returns the list of available policies."""
    response = client.get("/api/v1/policies")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["name"] == "default"


def test_get_default_policy():
    """GET /api/v1/policies/default returns default policy configuration."""
    response = client.get("/api/v1/policies/default")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "default"
    assert data["score"]["max_score"] == 80
    assert data["score"]["max_delta"] == 5


def test_validate_policy_valid():
    """POST /api/v1/policies/validate returns valid=True for valid config."""
    payload = {
        "name": "custom-security",
        "version": "1.1.0",
        "score": {"max_score": 60, "max_delta": 4},
        "findings": {"max_new_critical": 0},
    }
    response = client.post("/api/v1/policies/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["policy"]["name"] == "custom-security"
    assert data["errors"] == []


def test_validate_policy_invalid():
    """POST /api/v1/policies/validate returns valid=False with errors for invalid config."""
    payload = {
        "score": {"max_score": -10},
    }
    response = client.post("/api/v1/policies/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert len(data["errors"]) > 0


def test_evaluate_scan_api(tmp_path):
    """POST /api/v1/policies/scans/{scan_id}/evaluate evaluates scan against policy."""
    # Seed a scan in scan_db
    from app.models.domain.enums import ScanStatus
    from app.models.domain.scan import RepositoryMetadata

    scan = RepositoryScanResult(
        scan_id="test-scan-policy-1",
        repository=RepositoryMetadata(
            name="test-repo",
            path=str(tmp_path),
        ),
        status=ScanStatus.COMPLETED,
        manifest=None,
        findings=[],
        score=DebtScoreResult(
            total_score=15,
            tier=DebtScoreTier.VERY_LOW,
            category_scores={},
            total_findings=0,
            total_loc=100,
            analyzed_files=5,
            formula_summary="Sum of category scores",
        ),
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        duration_ms=1000.0,
    )
    scan_db.save_scan(scan)

    # Evaluate against default policy
    response = client.post("/api/v1/policies/scans/test-scan-policy-1/evaluate")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pass"
    assert data["score"] == 15
    assert data["passed"] is True

    # Evaluate against strict custom policy (max_score = 10 -> FAIL)
    custom_policy = {
        "name": "strict",
        "score": {"max_score": 10},
    }
    res_fail = client.post("/api/v1/policies/scans/test-scan-policy-1/evaluate", json=custom_policy)
    assert res_fail.status_code == 200
    data_fail = res_fail.json()
    assert data_fail["status"] == "fail"
    assert data_fail["passed"] is False
    assert len(data_fail["violations"]) == 1
