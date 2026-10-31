"""Tests for archive upload and local scanning support."""

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.errors import RepositorySecurityError
from app.main import app
from app.repository.sources import ArchiveUploadSource, LocalRepositorySource
from app.services.repository_service import repository_service

client = TestClient(app)


def test_archive_upload_source_valid_zip(tmp_path: Path):
    """ArchiveUploadSource extracts valid zip and discovers files."""
    zip_path = tmp_path / "valid_repo.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("app/main.py", "def hello():\n    return 'world'\n")
        zf.writestr("package.json", '{"name": "test-pkg"}\n')

    source = ArchiveUploadSource(archive_path=zip_path, name="test-upload")
    source.validate()
    root = source.get_root_path()
    assert root.exists()
    assert (root / "app" / "main.py").exists()

    scan = repository_service.execute_scan(source=source)
    assert scan.repository.name == "test-upload"
    assert scan.manifest is not None
    assert scan.manifest.repository.source_files >= 1


def test_archive_upload_source_path_traversal(tmp_path: Path):
    """ArchiveUploadSource rejects zip containing path traversal."""
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.py", "malicious_code = True\n")

    source = ArchiveUploadSource(archive_path=zip_path)
    with pytest.raises(RepositorySecurityError):
        source.validate()


def test_archive_upload_source_invalid_zip(tmp_path: Path):
    """ArchiveUploadSource rejects files that are not valid ZIPs."""
    bad_file = tmp_path / "bad.zip"
    bad_file.write_text("not a zip file", encoding="utf-8")

    source = ArchiveUploadSource(archive_path=bad_file)
    with pytest.raises(RepositorySecurityError):
        source.validate()


def test_api_upload_endpoint(tmp_path: Path):
    """Test /api/v1/repositories/upload endpoint."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("src/calc.py", "def add(a, b):\n    return a + b\n")

    zip_bytes = zip_buffer.getvalue()

    resp = client.post(
        "/api/v1/repositories/upload",
        files={"file": ("project.zip", zip_bytes, "application/zip")},
        data={"repo_name": "uploaded-api-test"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["scan_id"]
    assert data["repository"]["name"] == "uploaded-api-test"
    assert data["manifest"]["repository"]["source_files"] >= 1


def test_root_upload_endpoint(tmp_path: Path):
    """Test root /repositories/upload endpoint."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("index.js", "console.log('hello');\n")

    zip_bytes = zip_buffer.getvalue()

    resp = client.post(
        "/repositories/upload",
        files={"file": ("web-app.zip", zip_bytes, "application/zip")},
        data={"repo_name": "web-app"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["scan_id"]
    assert data["repository"]["name"] == "web-app"


def test_local_repository_source_resolves_quick_paths():
    """Verify quick paths resolve cleanly even when backend is in backend directory."""
    source = LocalRepositorySource(
        path="./backend/tests/fixtures/clean_python_project",
        name="clean-python-project",
    )
    source.validate()
    root = source.get_root_path()
    assert root.exists()
    assert (root / "main.py").exists()

