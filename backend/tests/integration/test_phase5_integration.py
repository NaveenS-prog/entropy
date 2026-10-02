"""Phase 5 End-to-End Integration Tests.

Validates:
1. Complete pipeline: Repository Ingestion -> Manifest -> Python Parser -> AnalysisContext ->
   Phase 3 Error Analyzer + Phase 5 Auth & Authz Analyzers -> Findings -> Scoring -> API Endpoints.
2. Integration repository containing:
   - Error-handling debt (ENT-ERR-002, ENT-ERR-003)
   - Authentication inconsistency (ENT-AUTH-002)
   - Authorization inconsistency (ENT-AUTHZ-002)
3. Scoring validation:
   - Phase 3 & Phase 5 findings both present
   - Category scores produced for all analyzed categories
   - Overall score dynamically changes
   - Removing security debt decreases category score
   - Clean codebase yields 0.0 scores for all analyzed categories
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.models.domain.enums import DebtScoreTier

client = TestClient(app)


def test_phase5_full_pipeline_and_scoring_validation(tmp_path: Path):
    """Verify Phase 3 + Phase 5 combined findings and scoring integration."""
    repo_dir = tmp_path / "enterprise_app"
    repo_dir.mkdir()
    routes_dir = repo_dir / "routes"
    routes_dir.mkdir()

    # 1. Error handling debt file (Phase 3)
    error_code = (
        "def process_order(order_id):\n"
        "    try:\n"
        "        charge(order_id)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    (repo_dir / "service.py").write_text(error_code, encoding="utf-8")

    # 2. Authentication inconsistency file (Phase 5)
    auth_code = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "def get_user(): return {'id': 1}\n"
        "\n"
        "@router.get('/profile/view')\n"
        "def profile_view(user=Depends(get_user)):\n"
        "    return {'view': True}\n"
        "\n"
        "@router.get('/profile/settings')\n"
        "def profile_settings(user=Depends(get_user)):\n"
        "    return {'settings': True}\n"
        "\n"
        "@router.get('/profile/export')\n"
        "def profile_export():\n"
        "    # Inconsistent authentication in /profile group\n"
        "    return {'data': []}\n"
    )
    (routes_dir / "profile.py").write_text(auth_code, encoding="utf-8")

    # 3. Authorization inconsistency file (Phase 5)
    authz_code = (
        "from fastapi import APIRouter, Depends, HTTPException\n"
        "router = APIRouter()\n"
        "\n"
        "def get_user(): return {'id': 1, 'role': 'user'}\n"
        "\n"
        "@router.get('/admin/users')\n"
        "def admin_users(user=Depends(get_user)):\n"
        "    if user.role != 'admin':\n"
        "        raise HTTPException(403)\n"
        "    return {'users': []}\n"
        "\n"
        "@router.get('/admin/roles')\n"
        "def admin_roles(user=Depends(get_user)):\n"
        "    if user.role != 'admin':\n"
        "        raise HTTPException(403)\n"
        "    return {'roles': []}\n"
        "\n"
        "@router.get('/admin/diagnostics')\n"
        "def admin_diagnostics(user=Depends(get_user)):\n"
        "    # Inconsistent authorization in /admin group\n"
        "    return {'diag': 'ok'}\n"
    )
    (routes_dir / "admin.py").write_text(authz_code, encoding="utf-8")

    # --- Step 1: Scan repository via API ---
    scan_resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["scan_id"]

    # --- Step 2: Verify Findings across Phase 3 and Phase 5 ---
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()

    categories_present = {f["category"] for f in findings}
    assert "error_handling" in categories_present
    assert "authentication_consistency" in categories_present
    assert "authorization_consistency" in categories_present

    rules_present = {f["rule_id"] for f in findings}
    assert "ENT-ERR-002" in rules_present or "ENT-ERR-003" in rules_present
    assert "ENT-AUTH-002" in rules_present
    assert "ENT-AUTHZ-002" in rules_present

    # --- Step 3: Verify Scoring Engine Output ---
    score_resp = client.get(f"/api/v1/scans/{scan_id}/score")
    assert score_resp.status_code == 200
    score_data = score_resp.json()

    assert score_data["status"] == "available"
    assert score_data["total_score"] > 0
    assert score_data["total_findings"] == len(findings)

    # All 3 active categories must be ANALYZED
    analyzed_cats = set(score_data["analyzed_categories"])
    assert "error_handling" in analyzed_cats
    assert "authentication_consistency" in analyzed_cats
    assert "authorization_consistency" in analyzed_cats

    cat_scores = score_data["category_scores"]
    assert cat_scores["error_handling"]["status"] == "analyzed"
    assert cat_scores["error_handling"]["score"] > 0
    assert cat_scores["authentication_consistency"]["status"] == "analyzed"
    assert cat_scores["authentication_consistency"]["score"] > 0
    assert cat_scores["authorization_consistency"]["status"] == "analyzed"
    assert cat_scores["authorization_consistency"]["score"] > 0

    assert cat_scores["code_duplication"]["status"] == "analyzed"
    assert cat_scores["architectural_consistency"]["status"] == "not_analyzed"
    assert cat_scores["architectural_consistency"]["score"] is None

    # Verify input_validation and logging_and_secrets are ANALYZED
    assert cat_scores["input_validation"]["status"] == "analyzed"
    assert cat_scores["logging_and_secrets"]["status"] == "analyzed"

    initial_total_score = score_data["total_score"]
    initial_auth_score = cat_scores["authentication_consistency"]["score"]

    # --- Step 4: Fix Authentication Debt and verify score decreases ---
    # Fix the auth inconsistency by protecting /profile/export
    clean_auth_code = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "def get_user(): return {'id': 1}\n"
        "\n"
        "@router.get('/profile/view')\n"
        "def profile_view(user=Depends(get_user)):\n"
        "    return {'view': True}\n"
        "\n"
        "@router.get('/profile/settings')\n"
        "def profile_settings(user=Depends(get_user)):\n"
        "    return {'settings': True}\n"
        "\n"
        "@router.get('/profile/export')\n"
        "def profile_export(user=Depends(get_user)):\n"
        "    # Fixed: authenticated with Depends\n"
        "    return {'data': []}\n"
    )
    (routes_dir / "profile.py").write_text(clean_auth_code, encoding="utf-8")

    # Rescan
    rescan_resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    assert rescan_resp.status_code == 201
    rescan_id = rescan_resp.json()["scan_id"]

    rescore_resp = client.get(f"/api/v1/scans/{rescan_id}/score")
    assert rescore_resp.status_code == 200
    rescore_data = rescore_resp.json()

    # Auth category score must have dropped to 0.0
    rescore_cats = rescore_data["category_scores"]
    assert rescore_cats["authentication_consistency"]["score"] < initial_auth_score
    assert rescore_cats["authentication_consistency"]["score"] == 0.0
    assert rescore_cats["authentication_consistency"]["finding_count"] == 0

    # Total score must have decreased
    assert rescore_data["total_score"] < initial_total_score

    # --- Step 5: Fix all remaining debt and verify 0 score ---
    # Fix error handling
    (repo_dir / "service.py").write_text("def process_order(order_id):\n    return True\n", encoding="utf-8")
    # Fix admin authorization by using a shared require_admin helper (clean architecture)
    clean_admin_code = (
        "from fastapi import APIRouter, Depends, HTTPException\n"
        "router = APIRouter()\n"
        "def get_user(): return {'id': 1, 'role': 'user'}\n"
        "def require_admin(user=Depends(get_user)):\n"
        "    if user.role != 'admin': raise HTTPException(403)\n"
        "    return user\n"
        "@router.get('/admin/users')\n"
        "def admin_users(admin=Depends(require_admin)):\n"
        "    return {'users': []}\n"
        "@router.get('/admin/roles')\n"
        "def admin_roles(admin=Depends(require_admin)):\n"
        "    return {'roles': []}\n"
        "@router.get('/admin/diagnostics')\n"
        "def admin_diagnostics(admin=Depends(require_admin)):\n"
        "    return {'diag': 'ok'}\n"
    )
    (routes_dir / "admin.py").write_text(clean_admin_code, encoding="utf-8")

    clean_scan_resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    assert clean_scan_resp.status_code == 201
    clean_scan_id = clean_scan_resp.json()["scan_id"]

    clean_score_resp = client.get(f"/api/v1/scans/{clean_scan_id}/score")
    assert clean_score_resp.status_code == 200
    clean_score_data = clean_score_resp.json()

    assert clean_score_data["total_findings"] == 0
    assert clean_score_data["total_score"] == 0
    assert clean_score_data["tier"] == DebtScoreTier.VERY_LOW.value

    clean_cats = clean_score_data["category_scores"]
    assert clean_cats["error_handling"]["score"] == 0.0
    assert clean_cats["authentication_consistency"]["score"] == 0.0
    assert clean_cats["authorization_consistency"]["score"] == 0.0
