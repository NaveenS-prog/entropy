"""Main FastAPI application entrypoint for Entropy."""

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.endpoints.repositories import _resolve_repository_id
from app.api.v1.router import api_router
from app.comparison.models import RepositoryTrendResponse, ScanComparisonResult
from app.comparison.service import comparison_service
from app.core.config import settings
from app.core.errors import (
    EntropyError,
    RepositoryLimitExceededError,
    RepositoryNotADirectoryError,
    RepositoryNotFoundError,
    RepositoryPermissionError,
    RepositorySecurityError,
)
from app.core.logging import logger, setup_logging
from app.models.domain.enums import DebtCategory, Severity
from app.models.domain.finding import Finding
from app.models.domain.manifest import RepositoryManifest
from app.models.domain.scoring import DebtScoreResult
from app.persistence.database import scan_db
from app.persistence.models import PaginatedScanSnapshots
from app.schemas.scan_schemas import ScanCreateRequest, ScanDetailResponse
from app.scoring.service import scoring_service
from app.services.analysis_service import analysis_service
from app.services.repository_service import repository_service

setup_logging()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description=(
        "Entropy: Architectural Security-Debt Analyzer for AI-Assisted Codebases. "
        "Identifies structural and architectural patterns that can accumulate hidden maintenance and security risk over time."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for local development and dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handlers ensuring clean structured errors without leaking stack traces
@app.exception_handler(RepositoryNotFoundError)
async def repository_not_found_handler(request: Request, exc: RepositoryNotFoundError):
    logger.warning("Repository not found: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc), "error_code": "REPOSITORY_NOT_FOUND"},
    )


@app.exception_handler(RepositoryNotADirectoryError)
async def repository_not_dir_handler(request: Request, exc: RepositoryNotADirectoryError):
    logger.warning("Repository path is not a directory: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_code": "NOT_A_DIRECTORY"},
    )


@app.exception_handler(RepositoryPermissionError)
async def repository_permission_handler(request: Request, exc: RepositoryPermissionError):
    logger.warning("Repository permission denied: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc), "error_code": "PERMISSION_DENIED"},
    )


@app.exception_handler(RepositorySecurityError)
async def repository_security_handler(request: Request, exc: RepositorySecurityError):
    logger.warning("Repository security boundary violation: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_code": "SECURITY_VIOLATION"},
    )


@app.exception_handler(RepositoryLimitExceededError)
async def repository_limit_handler(request: Request, exc: RepositoryLimitExceededError):
    logger.warning("Repository size or file limit exceeded: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_code": "LIMIT_EXCEEDED"},
    )


@app.exception_handler(EntropyError)
async def entropy_domain_handler(request: Request, exc: EntropyError):
    logger.warning("Domain error encountered: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_code": "DOMAIN_ERROR"},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server exception: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An unexpected error occurred during scan processing.",
            "error_code": "INTERNAL_SERVER_ERROR",
        },
    )


# Mount API V1 routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


# Root-level convenience routes matching product specification
@app.post(
    "/repositories/scan",
    response_model=ScanDetailResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Repositories"],
)
def root_scan_repository(request: ScanCreateRequest) -> ScanDetailResponse:
    """Ingest a repository via top-level endpoint."""
    scan_result = repository_service.execute_scan(
        repo_path=request.target_path,
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


@app.get("/scans/{scan_id}", response_model=ScanDetailResponse, tags=["Scans"])
def root_get_scan(scan_id: str) -> ScanDetailResponse:
    """Retrieve scan details via top-level endpoint."""
    scan_result = repository_service.get_scan(scan_id)
    if not scan_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
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


@app.get("/scans/{scan_id}/manifest", response_model=RepositoryManifest, tags=["Scans"])
def root_get_manifest(scan_id: str) -> RepositoryManifest:
    """Retrieve repository manifest via top-level endpoint."""
    manifest = repository_service.get_manifest(scan_id)
    if not manifest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest for scan '{scan_id}' not found",
        )
    return manifest


@app.get("/scans/{scan_id}/findings", response_model=list[Finding], tags=["Scans"])
def root_get_findings(
    scan_id: str,
    category: DebtCategory | None = None,
    severity: Severity | None = None,
    rule_id: str | None = None,
    file: str | None = None,
) -> list[Finding]:
    """Retrieve findings via top-level endpoint."""
    return analysis_service.analyze_scan(
        scan_id=scan_id,
        category=category,
        severity=severity,
        rule_id=rule_id,
        file_filter=file,
    )


@app.get("/scans/{scan_id}/score", response_model=DebtScoreResult, tags=["Scans"])
def root_get_score(scan_id: str) -> DebtScoreResult:
    """Retrieve or compute the Entropy Debt Score via top-level endpoint."""
    return scoring_service.get_score(scan_id)


@app.get("/repositories/{repository_id}/scans", response_model=PaginatedScanSnapshots, tags=["Repositories"])
def root_get_repository_scans(
    repository_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
    branch: str | None = Query(default=None),
) -> PaginatedScanSnapshots:
    """Retrieve paginated scan history for a repository."""
    resolved_id = _resolve_repository_id(repository_id)
    offset = (page - 1) * page_size
    items, total = scan_db.list_scans_for_repository(
        repository_id=resolved_id,
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


@app.get("/repositories/{repository_id}/trend", response_model=RepositoryTrendResponse, tags=["Repositories"])
def root_get_repository_trend(repository_id: str) -> RepositoryTrendResponse:
    """Retrieve chronological score trend for a repository."""
    resolved_id = _resolve_repository_id(repository_id)
    return comparison_service.build_repository_trend(resolved_id)


@app.get("/scans/{current_scan_id}/compare/{previous_scan_id}", response_model=ScanComparisonResult, tags=["Scans"])
def root_compare_scans(current_scan_id: str, previous_scan_id: str) -> ScanComparisonResult:
    """Compare two scans via top-level endpoint."""
    current_scan = repository_service.get_scan(current_scan_id)
    if not current_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Current scan '{current_scan_id}' not found",
        )
    previous_scan = repository_service.get_scan(previous_scan_id)
    if not previous_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Previous scan '{previous_scan_id}' not found",
        )

    # Ensure findings and scores are loaded
    if not current_scan.findings:
        analysis_service.analyze_scan(current_scan_id)
    if not current_scan.score:
        scoring_service.calculate_scan_score(current_scan_id)
    if not previous_scan.findings:
        analysis_service.analyze_scan(previous_scan_id)
    if not previous_scan.score:
        scoring_service.calculate_scan_score(previous_scan_id)

    return comparison_service.compare_scans(
        current_scan=current_scan, previous_scan=previous_scan
    )



@app.get("/", tags=["Root"])
def root() -> dict:
    """Root metadata greeting."""
    return {
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "api_v1": settings.API_V1_PREFIX,
        "status": "online",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
