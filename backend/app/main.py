"""Main FastAPI application entrypoint for Entropy."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.endpoints import (
    repositories as repos_ep,
)
from app.api.v1.endpoints import (
    scans as scans_ep,
)
from app.api.v1.router import api_router
from app.api.v1.security import is_authenticated_caller, verify_api_key
from app.comparison.models import RepositoryTrendResponse, ScanComparisonResult
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
from app.persistence.models import PaginatedScanSnapshots
from app.schemas.scan_schemas import ScanCreateRequest, ScanDetailResponse
from app.scoring.service import scoring_service
from app.services.analysis_service import analysis_service

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.API_KEY:
        if settings.ALLOW_LOCALHOST_NO_KEY:
            logger.warning(
                "SECURITY WARNING: ENTROPY_API_KEY is not configured! "
                "Localhost fallback is ENABLED (ENTROPY_ALLOW_LOCALHOST_NO_KEY=true). "
                "Requests from localhost are accepted without authentication. "
                "CRITICAL: Behind a reverse proxy, the client peer address is the proxy, "
                "meaning external requests may bypass authentication. DO NOT use this mode in production!"
            )
        else:
            logger.warning(
                "SECURITY NOTICE: ENTROPY_API_KEY is not configured and ENTROPY_ALLOW_LOCALHOST_NO_KEY=false. "
                "All protected API endpoints will reject requests with 401 Unauthorized."
            )
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description=(
        "Entropy: Architectural Security-Debt Analyzer for AI-Assisted Codebases. "
        "Identifies structural and architectural patterns that can accumulate hidden maintenance and security risk over time."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS for local development and dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
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
        content={"detail": "path is outside the allowed scan roots", "error_code": "SECURITY_VIOLATION"},
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
    dependencies=[Depends(verify_api_key)],
)
def root_scan_repository(request: ScanCreateRequest) -> ScanDetailResponse:
    """Ingest a repository via top-level endpoint."""
    return repos_ep.scan_repository(request)


@app.post(
    "/repositories/upload",
    response_model=ScanDetailResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Repositories"],
    dependencies=[Depends(verify_api_key)],
)
async def root_upload_repository(
    file: UploadFile = File(...),
    repo_name: str | None = Form(default=None),
    include_tests: bool = Form(default=False),
) -> ScanDetailResponse:
    """Upload a repository archive via top-level endpoint."""
    return await repos_ep.upload_repository_archive(
        file=file, repo_name=repo_name, include_tests=include_tests
    )


@app.get("/scans/{scan_id}", response_model=ScanDetailResponse, tags=["Scans"], dependencies=[Depends(verify_api_key)])
def root_get_scan(scan_id: str) -> ScanDetailResponse:
    """Retrieve scan details via top-level endpoint."""
    return scans_ep.get_scan(scan_id)


@app.get("/scans/{scan_id}/manifest", response_model=RepositoryManifest, tags=["Scans"], dependencies=[Depends(verify_api_key)])
def root_get_manifest(scan_id: str) -> RepositoryManifest:
    """Retrieve repository manifest via top-level endpoint."""
    return scans_ep.get_scan_manifest(scan_id)


@app.get("/scans/{scan_id}/findings", response_model=list[Finding], tags=["Scans"], dependencies=[Depends(verify_api_key)])
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


@app.get("/scans/{scan_id}/score", response_model=DebtScoreResult, tags=["Scans"], dependencies=[Depends(verify_api_key)])
def root_get_score(scan_id: str) -> DebtScoreResult:
    """Retrieve or compute the Entropy Debt Score via top-level endpoint."""
    return scoring_service.get_score(scan_id)


@app.get("/repositories/{repository_id}/scans", response_model=PaginatedScanSnapshots, tags=["Repositories"], dependencies=[Depends(verify_api_key)])
def root_get_repository_scans(
    repository_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
    branch: str | None = Query(default=None),
    is_authenticated: bool = Depends(is_authenticated_caller),
) -> PaginatedScanSnapshots:
    """Retrieve paginated scan history for a repository."""
    return repos_ep.get_repository_scans(
        repository_id=repository_id,
        page=page,
        page_size=page_size,
        status=status,
        branch=branch,
        is_authenticated=is_authenticated,
    )


@app.get("/repositories/{repository_id}/trend", response_model=RepositoryTrendResponse, tags=["Repositories"], dependencies=[Depends(verify_api_key)])
def root_get_repository_trend(repository_id: str) -> RepositoryTrendResponse:
    """Retrieve chronological score trend for a repository."""
    return repos_ep.get_repository_trend(repository_id)


@app.get("/scans/{current_scan_id}/compare/{previous_scan_id}", response_model=ScanComparisonResult, tags=["Scans"], dependencies=[Depends(verify_api_key)])
def root_compare_scans(current_scan_id: str, previous_scan_id: str) -> ScanComparisonResult:
    """Compare two scans via top-level endpoint."""
    return scans_ep.compare_scans(current_scan_id, previous_scan_id)



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
