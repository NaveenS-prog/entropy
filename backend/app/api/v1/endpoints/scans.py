"""Endpoints for initiating and querying repository scans."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status

from app.core.errors import RepositoryNotFoundError
from app.schemas.scan_schemas import ScanCreateRequest, ScanDetailResponse, ScanSummaryResponse
from app.services.scan_service import scan_service

router = APIRouter()


@router.post("", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
def trigger_scan(request: ScanCreateRequest) -> ScanDetailResponse:
    """Execute a deterministic static analysis scan over the specified repository path."""
    try:
        scan_result = scan_service.execute_scan(
            repo_path=request.repo_path,
            repo_name=request.repo_name,
        )
        return ScanDetailResponse(
            scan_id=scan_result.scan_id,
            repository=scan_result.repository,
            status=scan_result.status,
            findings=scan_result.findings,
            score=scan_result.score,
            started_at=scan_result.started_at,
            completed_at=scan_result.completed_at,
            duration_ms=scan_result.duration_ms,
            analyzers_executed=scan_result.analyzers_executed,
            errors=scan_result.errors,
        )
    except RepositoryNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan execution failed: {e}",
        ) from e


@router.get("", response_model=list[ScanSummaryResponse])
def list_scans() -> list[ScanSummaryResponse]:
    """Retrieve all completed scans."""
    scans = scan_service.list_scans()
    return [
        ScanSummaryResponse(
            scan_id=s.scan_id,
            repo_name=s.repository.name,
            repo_path=s.repository.path,
            branch=s.repository.branch,
            commit_hash=s.repository.commit_hash,
            status=s.status,
            total_score=s.score.total_score if s.score else None,
            tier=s.score.tier if s.score else None,
            total_findings=len(s.findings),
            total_loc=s.repository.total_loc,
            analyzed_files=s.score.analyzed_files if s.score else 0,
            started_at=s.started_at,
            duration_ms=s.duration_ms,
        )
        for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str) -> ScanDetailResponse:
    """Retrieve full details of a specific scan by its ID."""
    scan_result = scan_service.get_scan(scan_id)
    if not scan_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    return ScanDetailResponse(
        scan_id=scan_result.scan_id,
        repository=scan_result.repository,
        status=scan_result.status,
        findings=scan_result.findings,
        score=scan_result.score,
        started_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        duration_ms=scan_result.duration_ms,
        analyzers_executed=scan_result.analyzers_executed,
        errors=scan_result.errors,
    )


@router.post("/sample", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
def trigger_sample_scan() -> ScanDetailResponse:
    """Trigger a demo scan on the built-in fixture repository.

    Provides instant verification of the end-to-end pipeline without needing
    an external repository.
    """
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent.parent / "tests" / "fixtures" / "sample_repo"
    if not fixture_dir.exists():
        fixture_dir.mkdir(parents=True, exist_ok=True)
        # Create a sample python file demonstrating authentic debt
        sample_file = fixture_dir / "service.py"
        sample_file.write_text(
            'def handle_payment(payload):\n'
            '    try:\n'
            '        process_token(payload)\n'
            '    except Exception:\n'
            '        pass\n'
            '\n'
            'def fetch_user(user_id):\n'
            '    try:\n'
            '        return db_query(user_id)\n'
            '    except:\n'
            '        print("User query failed")\n'
        )

    scan_result = scan_service.execute_scan(
        repo_path=str(fixture_dir),
        repo_name="sample-ecommerce-service",
    )
    return ScanDetailResponse(
        scan_id=scan_result.scan_id,
        repository=scan_result.repository,
        status=scan_result.status,
        findings=scan_result.findings,
        score=scan_result.score,
        started_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        duration_ms=scan_result.duration_ms,
        analyzers_executed=scan_result.analyzers_executed,
        errors=scan_result.errors,
    )
