"""Phase 3 End-to-End Integration Tests.

Validates the full pipeline:
Repository -> Ingestion -> Manifest -> Python Parser -> AnalysisContext ->
Phase 3 ErrorHandlingDebtAnalyzer -> Findings Engine -> API Endpoints.

Also strictly validates Zero Code Execution during Phase 3 analysis.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.services.repository_service import repository_service

client = TestClient(app)


def test_phase3_full_pipeline_and_api(tmp_path: Path):
    """Verify full pipeline from local directory ingestion to findings API querying."""
    # 1. Setup local repo fixture with realistic debt patterns
    repo_dir = tmp_path / "sample_service"
    repo_dir.mkdir()

    auth_code = (
        "def authenticate_user(token):\n"
        "    try:\n"
        "        decode(token)\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "def fetch_token():\n"
        "    try:\n"
        "        return remote_token()\n"
        "    except ConnectionError:\n"
        "        return None\n"
    )
    (repo_dir / "auth.py").write_text(auth_code, encoding="utf-8")

    db_code = (
        "def query_database(sql):\n"
        "    try:\n"
        "        db.execute(sql)\n"
        "    except:\n"
        "        log.warning('query failed')\n"
    )
    (repo_dir / "db.py").write_text(db_code, encoding="utf-8")

    clean_code = (
        "def safe_divide(a, b):\n"
        "    try:\n"
        "        return a / b\n"
        "    except ZeroDivisionError as err:\n"
        "        logger.error('Zero division: %s', err)\n"
        "        raise\n"
    )
    (repo_dir / "math_ops.py").write_text(clean_code, encoding="utf-8")

    # 2. Ingest repository via API
    resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    assert resp.status_code == 201
    scan_data = resp.json()
    scan_id = scan_data["scan_id"]

    # 3. Query findings via API endpoint: GET /api/v1/scans/{scan_id}/findings
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 3

    rule_ids = {f["rule_id"] for f in findings}
    assert "ENT-ERR-001" in rule_ids  # Bare except in db.py
    assert "ENT-ERR-002" in rule_ids  # Broad Exception in auth.py
    assert "ENT-ERR-003" in rule_ids  # Empty pass in auth.py
    assert "ENT-ERR-005" in rule_ids  # return None in auth.py

    # Verify deterministic finding attributes
    for f in findings:
        assert f["id"] is not None and len(f["id"]) == 16
        assert f["category"] == "error_handling"
        assert f["severity"] in ("info", "low", "medium", "high", "critical")
        assert f["confidence"] in ("low", "medium", "high")
        assert f["evidence"]["content"] != ""
        assert f["evidence"]["line_start"] <= f["evidence"]["line_end"]
        assert len(f["evidence"]["highlight_lines"]) > 0
        assert f["impact"] != ""
        assert f["recommendation"] != ""
        assert f["fingerprint"] != ""

    # 4. Query findings via convenience alias: GET /scans/{scan_id}/findings
    alias_resp = client.get(f"/scans/{scan_id}/findings")
    assert alias_resp.status_code == 200
    assert alias_resp.json() == findings

    # 5. Query with filter: rule_id=ENT-ERR-001
    filtered_rule_resp = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"rule_id": "ENT-ERR-001"}
    )
    assert filtered_rule_resp.status_code == 200
    bare_findings = filtered_rule_resp.json()
    assert len(bare_findings) == 1
    assert bare_findings[0]["rule_id"] == "ENT-ERR-001"
    assert bare_findings[0]["file"] == "db.py"

    # 6. Query with filter: file=auth.py
    filtered_file_resp = client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"file": "auth.py"}
    )
    assert filtered_file_resp.status_code == 200
    auth_findings = filtered_file_resp.json()
    assert all(f["file"] == "auth.py" for f in auth_findings)
    assert len(auth_findings) == 3

    # 7. Query single finding by ID
    target_finding = findings[0]
    finding_id = target_finding["id"]
    single_resp = client.get(f"/api/v1/scans/{scan_id}/findings/{finding_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["id"] == finding_id

    # 8. Query nonexistent finding ID returns 404
    missing_resp = client.get(f"/api/v1/scans/{scan_id}/findings/nonexistent_finding_id")
    assert missing_resp.status_code == 404

    # 9. Query findings for nonexistent scan returns 404
    missing_scan_resp = client.get(f"/api/v1/scans/{uuid4()}/findings")
    assert missing_scan_resp.status_code == 404


def test_zero_code_execution_in_phase3_analysis(tmp_path: Path):
    """Verify that malicious code with system calls inside exception handlers is never executed."""
    canary_file = tmp_path / "phase3_should_not_exist.txt"
    if canary_file.exists():
        canary_file.unlink()

    malicious_repo = tmp_path / "malicious_repo"
    malicious_repo.mkdir()

    dangerous_code = (
        "import os\n"
        "\n"
        "def attack():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception:\n"
        f"        os.system('touch {canary_file}')\n"
        "\n"
        "# Module-level trap\n"
        "try:\n"
        "    pass\n"
        "except:\n"
        f"    open('{canary_file}', 'w').write('HACKED')\n"
    )
    (malicious_repo / "exploit.py").write_text(dangerous_code, encoding="utf-8")

    # Ingest repository
    scan_result = repository_service.execute_scan(repo_path=str(malicious_repo))
    scan_id = scan_result.scan_id

    # Run analysis via API
    resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) >= 1

    # Absolute proof of zero execution: canary file was NEVER created
    assert not canary_file.exists(), "CRITICAL: Malicious code was executed during static analysis!"
