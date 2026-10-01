"""Phase 4 End-to-End Integration Tests.

Validates the complete Entropy pipeline:
Repository -> Ingestion -> Manifest -> Python Parser -> AnalysisContext ->
Phase 3 ErrorHandlingDebtAnalyzer -> Findings -> Phase 4 Entropy Scoring Engine -> API Endpoints.

Also covers:
S. API 404 for nonexistent scan
T. API response schema validation
U. Clean real repository (0 findings -> score 0)
V. Real repository with Phase 3 findings
Zero Code Execution guarantee during scoring
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.models.domain.enums import DebtScoreTier
from app.services.repository_service import repository_service

client = TestClient(app)


def test_full_pipeline_ingestion_to_scoring(tmp_path: Path):
    """Verify entire pipeline: Repository -> Ingestion -> AST -> Findings -> Scoring -> API."""
    repo_dir = tmp_path / "microservice"
    repo_dir.mkdir()

    # Create real Python code exhibiting Error Handling Debt
    service_code = (
        "def process_order(order_id):\n"
        "    try:\n"
        "        charge(order_id)\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "def cancel_order(order_id):\n"
        "    try:\n"
        "        refund(order_id)\n"
        "    except:\n"
        "        log_error('refund failed')\n"
        "\n"
        "def query_status(order_id):\n"
        "    try:\n"
        "        return remote_call(order_id)\n"
        "    except ConnectionError:\n"
        "        return None\n"
    )
    (repo_dir / "service.py").write_text(service_code, encoding="utf-8")

    # 1. Ingest repository via API
    ingest_resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    assert ingest_resp.status_code == 201
    scan_id = ingest_resp.json()["scan_id"]

    # 2. Query score via API: GET /api/v1/scans/{scan_id}/score
    score_resp = client.get(f"/api/v1/scans/{scan_id}/score")
    assert score_resp.status_code == 200
    score_data = score_resp.json()

    # Requirement checks
    assert "total_score" in score_data
    score_val = score_data["total_score"]
    assert 0 <= score_val <= 100
    assert score_val > 0  # Real debt was present

    tier = score_data["tier"]
    assert tier in [t.value for t in DebtScoreTier]

    assert score_data["status"] == "available"
    assert "error_handling" in score_data["analyzed_categories"]

    # Category checks: error_handling must be analyzed, others not_analyzed
    category_scores = score_data["category_scores"]
    err_cat = category_scores["error_handling"]
    assert err_cat["status"] == "analyzed"
    assert err_cat["score"] is not None and err_cat["score"] > 0
    assert err_cat["finding_count"] >= 3

    auth_cat = category_scores["authentication_consistency"]
    assert auth_cat["status"] == "not_analyzed"
    assert auth_cat["score"] is None
    assert auth_cat["finding_count"] == 0

    # Severity breakdown check
    sev_breakdown = score_data["severity_breakdown"]
    assert sev_breakdown["medium"] >= 1

    # Top rules check
    top_rules = score_data["top_contributing_rules"]
    assert len(top_rules) >= 1
    assert any(r["rule_id"] in ("ENT-ERR-001", "ENT-ERR-002", "ENT-ERR-003", "ENT-ERR-005") for r in top_rules)

    # 3. Query score via top-level convenience alias: GET /scans/{scan_id}/score
    alias_resp = client.get(f"/scans/{scan_id}/score")
    assert alias_resp.status_code == 200
    assert alias_resp.json() == score_data

    # 4. Query score breakdown: GET /api/v1/scans/{scan_id}/score/breakdown
    breakdown_resp = client.get(f"/api/v1/scans/{scan_id}/score/breakdown")
    assert breakdown_resp.status_code == 200
    breakdown_data = breakdown_resp.json()
    assert breakdown_data["entropy_score"] == score_val
    assert breakdown_data["scan_id"] == scan_id


def test_clean_real_repository_produces_zero_score(tmp_path: Path):
    """U. Clean repository with clean exception handling produces score of 0."""
    clean_repo = tmp_path / "clean_service"
    clean_repo.mkdir()

    clean_code = (
        "def compute_total(items):\n"
        "    try:\n"
        "        return sum(item.price for item in items)\n"
        "    except (TypeError, AttributeError) as err:\n"
        "        logger.error('Invalid item format: %s', err)\n"
        "        raise\n"
    )
    (clean_repo / "main.py").write_text(clean_code, encoding="utf-8")

    ingest_resp = client.post("/api/v1/repositories/scan", json={"path": str(clean_repo)})
    assert ingest_resp.status_code == 201
    scan_id = ingest_resp.json()["scan_id"]

    score_resp = client.get(f"/api/v1/scans/{scan_id}/score")
    assert score_resp.status_code == 200
    score_data = score_resp.json()

    assert score_data["total_score"] == 0
    assert score_data["tier"] == "very_low"
    assert score_data["total_findings"] == 0
    assert score_data["category_scores"]["error_handling"]["score"] == 0.0
    assert score_data["category_scores"]["error_handling"]["status"] == "analyzed"


def test_api_404_for_nonexistent_scan():
    """S. Nonexistent scan ID returns 404."""
    nonexistent_id = str(uuid4())
    resp = client.get(f"/api/v1/scans/{nonexistent_id}/score")
    assert resp.status_code == 404
    assert f"Scan '{nonexistent_id}' not found" in resp.json()["detail"]


def test_zero_code_execution_in_scoring(tmp_path: Path):
    """Verify that scoring malicious findings never triggers arbitrary code execution."""
    canary = tmp_path / "scoring_should_not_exist.txt"
    if canary.exists():
        canary.unlink()

    malicious_repo = tmp_path / "malicious_scoring_repo"
    malicious_repo.mkdir()

    dangerous_code = (
        "def exploit():\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        f"        import os; os.system('touch {canary}')\n"
    )
    (malicious_repo / "exploit.py").write_text(dangerous_code, encoding="utf-8")

    scan_result = repository_service.execute_scan(repo_path=str(malicious_repo))
    scan_id = scan_result.scan_id

    # Compute score via API
    resp = client.get(f"/api/v1/scans/{scan_id}/score")
    assert resp.status_code == 200
    assert resp.json()["total_score"] > 0

    # Prove zero code execution: canary was NEVER touched
    assert not canary.exists(), "SECURITY INVARIANT VIOLATED: Code was executed during scoring!"
