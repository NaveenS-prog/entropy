"""Unit tests for scan lifecycle states and invariant guarantees."""

from pathlib import Path

import pytest

from app.core.errors import RepositoryNotFoundError
from app.models.domain.enums import ScanStatus
from app.services.repository_service import RepositoryService

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_scan_lifecycle_completed():
    project_dir = FIXTURES_DIR / "clean_python_project"
    service = RepositoryService()

    result = service.execute_scan(repo_path=str(project_dir), repo_name="test-repo")

    assert result.status == ScanStatus.COMPLETED
    assert result.scan_id is not None
    assert result.repository.name == "test-repo"
    assert result.manifest is not None
    assert result.completed_at is not None
    assert result.duration_ms is not None and result.duration_ms >= 0


def test_scan_lifecycle_failed_on_missing_dir():
    service = RepositoryService()
    with pytest.raises(RepositoryNotFoundError):
        service.execute_scan(repo_path="/nonexistent/path/for/failure/test")


def test_phase_1_invariants_no_fake_findings_or_scores():
    """Verify strictly:

    - No fake security findings
    - No fake scoring
    - Real repository metadata only
    """
    project_dir = FIXTURES_DIR / "clean_python_project"
    service = RepositoryService()
    result = service.execute_scan(repo_path=str(project_dir))

    # Strict Constitution & Phase 1 invariants
    assert result.findings == []
    assert result.score is None
    assert result.analyzers_executed == []
    assert result.errors == []
    assert result.manifest is not None
    assert result.manifest.repository.source_files == 3
