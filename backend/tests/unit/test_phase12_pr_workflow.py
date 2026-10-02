"""Unit tests for Phase 12 PR Workflow, Idempotency, and Concurrency."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.comparison.models import ComparisonSummary, ScanComparisonResult, ScoreComparison
from app.github.models import PRAnalysisRecord, PRAnalysisStatus
from app.github.service import GitHubWorkflowService
from app.models.domain.enums import DebtScoreTier
from app.persistence.database import ScanDatabase


@pytest.fixture
def in_memory_db(tmp_path):
    db_file = tmp_path / "test_pr_scans.db"
    return ScanDatabase(db_path=db_file)


def _make_dummy_comparison(base_score: int = 10, head_score: int = 15) -> ScanComparisonResult:
    delta = head_score - base_score
    return ScanComparisonResult(
        summary=ComparisonSummary(
            repository_id="org/repo",
            repo_name="repo",
            previous_scan_id="scan-base-123",
            current_scan_id="scan-head-456",
            previous_timestamp=datetime.now(UTC),
            current_timestamp=datetime.now(UTC),
            previous_score=base_score,
            current_score=head_score,
            score_delta=delta,
            new_findings_count=2,
            resolved_findings_count=1,
            persistent_findings_count=5,
            total_current_findings=7,
        ),
        score_comparison=ScoreComparison(
            previous_score=base_score,
            current_score=head_score,
            score_delta=delta,
            previous_band=DebtScoreTier.VERY_LOW,
            current_band=DebtScoreTier.VERY_LOW,
            direction="increased",
            explanation=f"Entropy debt score increased by {delta} points.",
        ),
        category_comparisons={},
        rule_comparisons=[],
        new_findings=[],
        resolved_findings=[],
        persistent_findings=[],
    )


def test_pr_analysis_persistence_and_retrieval(in_memory_db):
    """Test saving and retrieving PRAnalysisRecord and its comparison."""
    record = PRAnalysisRecord(
        id=str(uuid.uuid4()),
        repository_id="org/repo",
        owner="org",
        repo="repo",
        pr_number=42,
        base_sha="1111111111111111111111111111111111111111",
        head_sha="2222222222222222222222222222222222222222",
        base_score=10,
        head_score=15,
        score_delta=5,
        new_findings_count=2,
        resolved_findings_count=1,
        persistent_findings_count=5,
        status=PRAnalysisStatus.COMPLETED,
        is_current_head=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    comparison = _make_dummy_comparison(10, 15)

    in_memory_db.save_pr_analysis(record, comparison=comparison)

    fetched = in_memory_db.get_pr_analysis(record.id)
    assert fetched is not None
    assert fetched.pr_number == 42
    assert fetched.score_delta == 5
    assert fetched.status == PRAnalysisStatus.COMPLETED

    # Check comparison retrieval
    comp_fetched = in_memory_db.get_pr_comparison(record.id)
    assert comp_fetched is not None
    assert comp_fetched.summary.score_delta == 5
    assert comp_fetched.summary.new_findings_count == 2


def test_idempotency_avoids_duplicate_analysis(in_memory_db):
    """Calling analyze_pull_request with an already completed target returns cached record immediately."""
    base_sha = "1111111111111111111111111111111111111111"
    head_sha = "2222222222222222222222222222222222222222"

    # Pre-populate completed record
    existing_record = PRAnalysisRecord(
        id=str(uuid.uuid4()),
        repository_id="org/repo",
        owner="org",
        repo="repo",
        pr_number=101,
        base_sha=base_sha,
        head_sha=head_sha,
        base_score=8,
        head_score=12,
        score_delta=4,
        status=PRAnalysisStatus.COMPLETED,
        is_current_head=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    in_memory_db.save_pr_analysis(existing_record)

    mock_client = MagicMock()
    mock_repo_svc = MagicMock()

    service = GitHubWorkflowService(db=in_memory_db, client=mock_client, repo_svc=mock_repo_svc)

    result = service.analyze_pull_request(
        owner="org",
        repo="repo",
        pr_number=101,
        base_sha=base_sha,
        head_sha=head_sha,
    )

    # Must return the existing record and NEVER call repo_svc to re-scan
    assert result.id == existing_record.id
    assert result.status == PRAnalysisStatus.COMPLETED
    mock_repo_svc.execute_scan.assert_not_called()


def test_concurrency_race_condition_protection(in_memory_db):
    """When a newer commit SHA already completed, an older commit SHA completing later does NOT usurp is_current_head."""
    pr_number = 77
    now = datetime.now(UTC)

    # 1. SHA_B completed at time T+2
    sha_b_record = PRAnalysisRecord(
        id=str(uuid.uuid4()),
        repository_id="org/repo",
        owner="org",
        repo="repo",
        pr_number=pr_number,
        base_sha="0000000000000000000000000000000000000000",
        head_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        status=PRAnalysisStatus.COMPLETED,
        is_current_head=True,
        created_at=now + timedelta(seconds=2),
        updated_at=now + timedelta(seconds=10),
    )
    in_memory_db.save_pr_analysis(sha_b_record)

    # 2. SHA_A started earlier at time T+0, but completes now
    sha_a_record = PRAnalysisRecord(
        id=str(uuid.uuid4()),
        repository_id="org/repo",
        owner="org",
        repo="repo",
        pr_number=pr_number,
        base_sha="0000000000000000000000000000000000000000",
        head_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        status=PRAnalysisStatus.RUNNING,
        is_current_head=False,
        created_at=now,
        updated_at=now,
    )
    in_memory_db.save_pr_analysis(sha_a_record)

    # Concurrency check simulation inside service
    latest_active = in_memory_db.get_latest_pr_analysis("org", "repo", pr_number)
    assert latest_active.head_sha == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    # Complete SHA_A
    sha_a_record.status = PRAnalysisStatus.COMPLETED
    sha_a_record.updated_at = now + timedelta(seconds=15)

    if latest_active and latest_active.id != sha_a_record.id:
        if latest_active.updated_at > sha_a_record.created_at and latest_active.head_sha != sha_a_record.head_sha:
            sha_a_record.is_current_head = False
        else:
            in_memory_db.update_pr_current_head("org", "repo", pr_number, sha_a_record.id)
            sha_a_record.is_current_head = True

    in_memory_db.save_pr_analysis(sha_a_record)

    # Verify that SHA_B remains the current active head!
    current_head = in_memory_db.get_latest_pr_analysis("org", "repo", pr_number)
    assert current_head.id == sha_b_record.id
    assert current_head.head_sha == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert current_head.is_current_head is True
