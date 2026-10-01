"""API endpoints for repository ingestion and manifest operations."""

from fastapi import APIRouter, HTTPException, status

from app.models.domain.manifest import RepositoryManifest
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
