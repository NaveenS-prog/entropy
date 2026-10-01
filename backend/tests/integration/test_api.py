"""Integration tests for FastAPI endpoints."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["service"] == "SilentGuard"


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["active_analyzers_count"] >= 1
    assert data["total_rules_count"] >= 2
    assert "python" in data["supported_languages"]


def test_analyzers_endpoint():
    response = client.get("/api/v1/analyzers")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["category"] == "error_handling"

    rules_resp = client.get("/api/v1/analyzers/rules")
    assert rules_resp.status_code == 200
    rules = rules_resp.json()
    assert any(r["rule_id"] == "ERR-001" for r in rules)


def test_sample_scan_workflow():
    # 1. Trigger sample scan
    scan_resp = client.post("/api/v1/scans/sample")
    assert scan_resp.status_code == 201
    scan = scan_resp.json()
    scan_id = scan["scan_id"]

    assert scan["status"] == "completed"
    assert len(scan["findings"]) >= 1
    assert scan["score"] is not None
    assert scan["score"]["total_score"] >= 0

    # 2. Query scan by ID
    get_resp = client.get(f"/api/v1/scans/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["scan_id"] == scan_id

    # 3. Query findings for scan
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1

    first_finding_id = findings[0]["id"]

    # 4. Query architectural explanation
    explain_resp = client.get(f"/api/v1/scans/{scan_id}/findings/{first_finding_id}/explain")
    assert explain_resp.status_code == 200
    explanation = explain_resp.json()
    assert explanation["finding_id"] == first_finding_id
    assert "architectural_context" in explanation
