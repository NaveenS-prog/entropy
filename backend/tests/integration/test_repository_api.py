"""Integration tests for Repository Ingestion and Manifest REST API endpoints."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_post_repositories_scan_with_path():
    repo_path = str(FIXTURES_DIR / "clean_python_project")
    response = client.post(
        "/api/v1/repositories/scan",
        json={"path": repo_path, "repo_name": "clean-python-test"},
    )
    assert response.status_code == 201
    data = response.json()

    assert "scan_id" in data
    assert data["status"] == "completed"
    assert data["repository"]["name"] == "clean-python-test"
    assert data["repository"]["scannable_files"] == 3
    assert data["manifest"] is not None
    assert data["manifest"]["repository"]["source_files"] == 3
    assert data["findings"] == []
    assert data["score"] is None

    scan_id = data["scan_id"]

    # Retrieve scan by id
    get_resp = client.get(f"/api/v1/scans/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["scan_id"] == scan_id

    # Retrieve manifest by id
    manifest_resp = client.get(f"/api/v1/scans/{scan_id}/manifest")
    assert manifest_resp.status_code == 200
    manifest = manifest_resp.json()
    assert manifest["repository"]["name"] == "clean-python-test"
    assert len(manifest["files"]) == 3
    assert "python" in manifest["languages"]


def test_post_scans_alias_endpoint():
    repo_path = str(FIXTURES_DIR / "mixed_language_project")
    response = client.post(
        "/api/v1/scans",
        json={"repo_path": repo_path},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "completed"
    assert data["manifest"] is not None
    assert len(data["manifest"]["languages"]) >= 5


def test_top_level_convenience_routes():
    repo_path = str(FIXTURES_DIR / "clean_python_project")
    response = client.post(
        "/repositories/scan",
        json={"path": repo_path, "repo_name": "root-endpoint-test"},
    )
    assert response.status_code == 201
    data = response.json()
    scan_id = data["scan_id"]

    # Root /scans/{scan_id}
    scan_get = client.get(f"/scans/{scan_id}")
    assert scan_get.status_code == 200

    # Root /scans/{scan_id}/manifest
    manifest_get = client.get(f"/scans/{scan_id}/manifest")
    assert manifest_get.status_code == 200
    assert manifest_get.json()["repository"]["name"] == "root-endpoint-test"


def test_scan_nonexistent_repository_error_handling():
    response = client.post(
        "/api/v1/repositories/scan",
        json={"path": "/nonexistent/repo/path/xyz"},
    )
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    # Ensure no raw python traceback is leaked
    assert "Traceback" not in data["detail"]
    assert "error_code" in data
    assert data["error_code"] == "REPOSITORY_NOT_FOUND"


def test_scan_file_not_directory_error_handling(tmp_path):
    file_path = tmp_path / "single_file.py"
    file_path.write_text("x = 10\n")

    response = client.post(
        "/api/v1/repositories/scan",
        json={"path": str(file_path)},
    )
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "Traceback" not in data["detail"]
    assert data["error_code"] == "NOT_A_DIRECTORY"


def test_get_nonexistent_scan_manifest():
    response = client.get("/api/v1/scans/non-existent-scan-id/manifest")
    assert response.status_code == 404
