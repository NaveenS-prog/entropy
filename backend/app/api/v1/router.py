"""API v1 master router."""

from fastapi import APIRouter, Depends

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
from app.api.v1.security import verify_api_key

api_router = APIRouter()

# Public & HMAC-verified routes
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])

# Authenticated routes
api_router.include_router(policies.router, tags=["Policies"], dependencies=[Depends(verify_api_key)])
api_router.include_router(analyzers.router, prefix="/analyzers", tags=["Analyzers"], dependencies=[Depends(verify_api_key)])
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories"], dependencies=[Depends(verify_api_key)])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"], dependencies=[Depends(verify_api_key)])
api_router.include_router(findings.router, prefix="/scans", tags=["Findings"], dependencies=[Depends(verify_api_key)])
api_router.include_router(findings.direct_router, prefix="/findings", tags=["Findings"], dependencies=[Depends(verify_api_key)])
api_router.include_router(scoring.router, prefix="/scans", tags=["Scoring"], dependencies=[Depends(verify_api_key)])
api_router.include_router(github_prs.router, prefix="/github/prs", tags=["GitHub PRs"], dependencies=[Depends(verify_api_key)])

