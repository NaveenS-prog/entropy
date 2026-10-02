"""Phase 6 Comprehensive Integration Test: Multi-category debt scanning, progressive remediation, and zero-debt scoring."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_phase6_progressive_remediation_lifecycle(tmp_path: Path):
    """Verify full Phase 6 lifecycle:

    1. Ingest repository with debt in all 5 active categories:
       - error_handling
       - authentication_consistency
       - authorization_consistency
       - input_validation
       - logging_and_secrets
    2. Verify all 5 categories are ANALYZED with score > 0.
    3. Verify remaining 2 categories (code_duplication, architectural_consistency) are NOT_ANALYZED with null scores.
    4. Progressively remediate debt in each category and verify:
       - Category finding count and score decreases
       - Overall total score never increases
    5. When all debt is fixed:
       - All analyzed category scores are 0.0
       - Final Entropy score is 0
    """
    repo_dir = tmp_path / "progressive_debt_repo"
    repo_dir.mkdir()
    routes_dir = repo_dir / "routes"
    routes_dir.mkdir()

    # --- Setup File 1: Error Handling Debt ---
    error_code = (
        "def process_order(order_id):\n"
        "    try:\n"
        "        return order_id * 2\n"
        "    except Exception:\n"
        "        pass\n"
    )
    (repo_dir / "service.py").write_text(error_code, encoding="utf-8")

    # --- Setup File 2: Authentication Inconsistency ---
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
        "    # Inconsistent unauthenticated endpoint\n"
        "    return {'data': []}\n"
    )
    (routes_dir / "profile.py").write_text(auth_code, encoding="utf-8")

    # --- Setup File 3: Authorization Inconsistency ---
    authz_code = (
        "from fastapi import APIRouter, Depends, HTTPException\n"
        "router = APIRouter()\n"
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
        "    # Inconsistent: authenticated but lacks admin check\n"
        "    return {'diag': 'ok'}\n"
    )
    (routes_dir / "admin.py").write_text(authz_code, encoding="utf-8")

    # --- Setup File 4: Input Validation Debt ---
    input_code = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "def get_user(): return {'id': 1}\n"
        "\n"
        "@router.post('/billing/charge')\n"
        "def charge_customer(raw_payload: dict, user=Depends(get_user)):\n"
        "    # ENT-INPUT-001: Unvalidated external dictionary payload\n"
        "    amount = raw_payload.get('amount')\n"
        "    return {'charged': amount}\n"
    )
    (routes_dir / "billing.py").write_text(input_code, encoding="utf-8")

    # --- Setup File 5: Logging & Secrets Debt ---
    log_secret_code = (
        "import logging, os\n"
        "logger = logging.getLogger('sec')\n"
        "\n"
        "# ENT-LOG-002: Hardcoded live API key\n"
        "STRIPE_API_KEY = 'sk_live_nonproduction_test_token_12345'\n"
        "\n"
        "def authenticate(password: str):\n"
        "    # ENT-LOG-001: Sensitive password in logs\n"
        "    logger.info('User password is %s', password)\n"
        "    return True\n"
    )
    (repo_dir / "security.py").write_text(log_secret_code, encoding="utf-8")

    # --- Step 1: Initial Scan ---
    scan_resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["scan_id"]

    score_resp = client.get(f"/api/v1/scans/{scan_id}/score")
    assert score_resp.status_code == 200
    score_data = score_resp.json()

    cat_scores = score_data["category_scores"]

    # All 5 active categories must be ANALYZED with positive score
    active_categories = (
        "error_handling",
        "authentication_consistency",
        "authorization_consistency",
        "input_validation",
        "logging_and_secrets",
    )
    for cat in active_categories:
        assert cat_scores[cat]["status"] == "analyzed", f"Expected {cat} to be analyzed"
        assert cat_scores[cat]["score"] > 0, f"Expected {cat} score > 0"
        assert cat_scores[cat]["finding_count"] > 0, f"Expected {cat} finding_count > 0"

    # Remaining 2 categories must remain NOT_ANALYZED with null scores
    for unanalyzed in ("code_duplication", "architectural_consistency"):
        assert cat_scores[unanalyzed]["status"] == "not_analyzed"
        assert cat_scores[unanalyzed]["score"] is None

    score_v0 = score_data["total_score"]
    assert score_v0 > 0

    # --- Step 2: Fix Input Validation Debt ---
    clean_input_code = (
        "from fastapi import APIRouter, Depends\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "def get_user(): return {'id': 1}\n"
        "\n"
        "class ChargeRequest(BaseModel):\n"
        "    amount: int\n"
        "\n"
        "@router.post('/billing/charge')\n"
        "def charge_customer(payload: ChargeRequest, user=Depends(get_user)):\n"
        "    return {'charged': payload.amount}\n"
    )
    (routes_dir / "billing.py").write_text(clean_input_code, encoding="utf-8")

    rescan1 = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    score_data1 = client.get(f"/api/v1/scans/{rescan1.json()['scan_id']}/score").json()
    cats1 = score_data1["category_scores"]

    assert cats1["input_validation"]["score"] == 0.0
    assert cats1["input_validation"]["finding_count"] == 0
    assert score_data1["total_score"] <= score_v0

    # --- Step 3: Fix Logging & Secrets Debt ---
    clean_log_code = (
        "import logging, os\n"
        "logger = logging.getLogger('sec')\n"
        "STRIPE_API_KEY = os.getenv('STRIPE_API_KEY')\n"
        "\n"
        "def authenticate(password: str):\n"
        "    logger.info('User authenticated successfully')\n"
        "    return True\n"
    )
    (repo_dir / "security.py").write_text(clean_log_code, encoding="utf-8")

    rescan2 = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    score_data2 = client.get(f"/api/v1/scans/{rescan2.json()['scan_id']}/score").json()
    cats2 = score_data2["category_scores"]

    assert cats2["logging_and_secrets"]["score"] == 0.0
    assert cats2["logging_and_secrets"]["finding_count"] == 0
    assert score_data2["total_score"] <= score_data1["total_score"]

    # --- Step 4: Fix Authentication Inconsistency ---
    clean_auth_code = (
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
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
        "    return {'data': []}\n"
    )
    (routes_dir / "profile.py").write_text(clean_auth_code, encoding="utf-8")

    rescan3 = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    score_data3 = client.get(f"/api/v1/scans/{rescan3.json()['scan_id']}/score").json()
    cats3 = score_data3["category_scores"]

    assert cats3["authentication_consistency"]["score"] == 0.0
    assert cats3["authentication_consistency"]["finding_count"] == 0
    assert score_data3["total_score"] <= score_data2["total_score"]

    # --- Step 5: Fix Authorization Inconsistency ---
    clean_authz_code = (
        "from fastapi import APIRouter, Depends, HTTPException\n"
        "router = APIRouter()\n"
        "def get_user(): return {'id': 1, 'role': 'user'}\n"
        "def require_admin(user=Depends(get_user)):\n"
        "    if user.role != 'admin': raise HTTPException(403)\n"
        "    return user\n"
        "\n"
        "@router.get('/admin/users')\n"
        "def admin_users(admin=Depends(require_admin)):\n"
        "    return {'users': []}\n"
        "\n"
        "@router.get('/admin/roles')\n"
        "def admin_roles(admin=Depends(require_admin)):\n"
        "    return {'roles': []}\n"
        "\n"
        "@router.get('/admin/diagnostics')\n"
        "def admin_diagnostics(admin=Depends(require_admin)):\n"
        "    return {'diag': 'ok'}\n"
    )
    (routes_dir / "admin.py").write_text(clean_authz_code, encoding="utf-8")

    rescan4 = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    score_data4 = client.get(f"/api/v1/scans/{rescan4.json()['scan_id']}/score").json()
    cats4 = score_data4["category_scores"]

    assert cats4["authorization_consistency"]["score"] == 0.0
    assert cats4["authorization_consistency"]["finding_count"] == 0
    assert score_data4["total_score"] <= score_data3["total_score"]

    # --- Step 6: Fix Error Handling Debt ---
    clean_error_code = "def process_order(order_id):\n    return order_id * 2\n"
    (repo_dir / "service.py").write_text(clean_error_code, encoding="utf-8")

    rescan5 = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    score_data5 = client.get(f"/api/v1/scans/{rescan5.json()['scan_id']}/score").json()
    cats5 = score_data5["category_scores"]

    # All active categories must now be 0.0
    for cat in active_categories:
        assert cats5[cat]["score"] == 0.0
        assert cats5[cat]["finding_count"] == 0

    assert score_data5["total_findings"] == 0
    assert score_data5["total_score"] == 0
    assert score_data5["tier"] == "very_low"
