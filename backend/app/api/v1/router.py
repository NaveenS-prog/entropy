"""API v1 master router."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    analyzers,
    findings,
    github_prs,
    health,
    policies,
    repositories,
    scans,
    scoring,
    webhooks,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(policies.router, tags=["Policies"])
api_router.include_router(analyzers.router, prefix="/analyzers", tags=["Analyzers"])
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(findings.router, prefix="/scans", tags=["Findings"])
api_router.include_router(findings.direct_router, prefix="/findings", tags=["Findings"])
api_router.include_router(scoring.router, prefix="/scans", tags=["Scoring"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
api_router.include_router(github_prs.router, prefix="/github/prs", tags=["GitHub PRs"])

