"""API v1 master router."""

from fastapi import APIRouter

from app.api.v1.endpoints import analyzers, findings, health, repositories, scans, scoring

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(analyzers.router, prefix="/analyzers", tags=["Analyzers"])
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(findings.router, prefix="/scans", tags=["Findings"])
api_router.include_router(scoring.router, prefix="/scans", tags=["Scoring"])
