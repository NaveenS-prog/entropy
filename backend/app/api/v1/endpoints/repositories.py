"""API endpoints for repository ingestion and manifest operations."""

from fastapi import APIRouter, HTTPException, Query, status

from app.comparison.models import RepositoryTrendResponse
from app.comparison.service import comparison_service
from app.models.domain.manifest import RepositoryManifest
from app.persistence.database import scan_db
from app.persistence.models import PaginatedScanSnapshots
from app.schemas.scan_schemas import ScanCreateRequest, ScanDetailResponse
from app.services.repository_service import repository_service

router = APIRouter()


@router.post("/scan", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
def scan_repository(request: ScanCreateRequest) -> ScanDetailResponse:
    """Ingest a repository, discover source files, detect languages, and generate a manifest.

    INVARIANT: Does not execute untrusted repository code. Does not generate fake findings.
    """
    target = request.target_path
    scan_result = repository_service.execute_scan(
        repo_path=target,
        repo_name=request.repo_name,
    )
    return ScanDetailResponse(
        scan_id=scan_result.scan_id,
        repository=scan_result.repository,
        status=scan_result.status,
        manifest=scan_result.manifest,
        findings=scan_result.findings,
        score=scan_result.score,
        started_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        duration_ms=scan_result.duration_ms,
        analyzers_executed=scan_result.analyzers_executed,
        errors=scan_result.errors,
    )


@router.get("/{scan_id}/manifest", response_model=RepositoryManifest)
def get_repository_manifest(scan_id: str) -> RepositoryManifest:
    """Retrieve the detailed repository manifest for an ingested repository scan."""
    manifest = repository_service.get_manifest(scan_id)
    if not manifest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest for scan '{scan_id}' not found",
        )
    return manifest


@router.get("/{repository_id}/scans", response_model=PaginatedScanSnapshots)
def get_repository_scans(
    repository_id: str,
    page: int = Query(default=1, ge=1, description="Page number starting at 1"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status: str | None = Query(default=None, description="Filter by status (e.g. completed, failed)"),
    branch: str | None = Query(default=None, description="Filter by branch name"),
) -> PaginatedScanSnapshots:
    """List historical scan snapshots for a repository with pagination, newest first."""
    resolved_repo_id = _resolve_repository_id(repository_id)
    offset = (page - 1) * page_size

    items, total = scan_db.list_scans_for_repository(
        repository_id=resolved_repo_id,
        limit=page_size,
        offset=offset,
        status=status,
        branch=branch,
    )

    total_pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedScanSnapshots(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{repository_id}/trend", response_model=RepositoryTrendResponse)
def get_repository_trend(repository_id: str) -> RepositoryTrendResponse:
    """Retrieve chronological debt score progression and category trends for a repository."""
    resolved_repo_id = _resolve_repository_id(repository_id)
    return comparison_service.build_repository_trend(resolved_repo_id)


def _resolve_repository_id(repo_identifier: str) -> str:
    """Resolve repository identifier from hex id, repo name, or recent scan id."""
    # Check if this identifier already has records in the database
    with scan_db._get_connection() as conn:
        row = conn.execute(
            "SELECT repository_id FROM scan_snapshots WHERE repository_id = ? LIMIT 1;",
            (repo_identifier,),
        ).fetchone()
        if row:
            return row["repository_id"]

        # Check by repo_name
        name_row = conn.execute(
            "SELECT repository_id FROM scan_snapshots WHERE repo_name = ? ORDER BY started_at DESC LIMIT 1;",
            (repo_identifier,),
        ).fetchone()
        if name_row:
            return name_row["repository_id"]

        # Check if identifier was a scan_id
        scan_row = conn.execute(
            "SELECT repository_id FROM scan_snapshots WHERE scan_id = ? LIMIT 1;",
            (repo_identifier,),
        ).fetchone()
        if scan_row:
            return scan_row["repository_id"]

    return repo_identifier

