"""API endpoints for inspecting and triggering GitHub Pull Request debt workflows."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status

from app.comparison.models import ScanComparisonResult
from app.github.models import PRAnalysisRecord, PRAnalysisTriggerRequest
from app.github.service import github_workflow_service
from app.persistence.database import scan_db

logger = logging.getLogger("entropy.api.github_prs")
router = APIRouter()


@router.post("/{owner}/{repo}/{pr_number}/analyze", response_model=PRAnalysisRecord)
def trigger_pr_analysis(
    owner: str,
    repo: str,
    pr_number: int,
    request: PRAnalysisTriggerRequest | None = None,
) -> PRAnalysisRecord:
    """Trigger or re-execute deterministic Base vs Head scan comparison for a Pull Request."""
    base_sha = request.base_sha if request else None
    head_sha = request.head_sha if request else None
    base_branch = request.base_branch if request else None
    head_branch = request.head_branch if request else None
    source_path = request.source_path if request else None

    # If SHAs were not supplied directly in the request, query GitHub API
    if not base_sha or not head_sha:
        pr_info = github_workflow_service.client.get_pull_request(owner, repo, pr_number)
        if not pr_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Pull request #{pr_number} could not be resolved from GitHub API",
            )
        base_sha = base_sha or pr_info.base_sha
        head_sha = head_sha or pr_info.head_sha
        base_branch = base_branch or pr_info.base_branch
        head_branch = head_branch or pr_info.head_branch

    try:
        return github_workflow_service.analyze_pull_request(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            base_sha=base_sha,
            head_sha=head_sha,
            base_branch=base_branch,
            head_branch=head_branch,
            source_repo_path=source_path,
            force_reanalyze=True,
        )
    except Exception as exc:
        logger.exception("Failed to execute PR analysis: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PR analysis failed: {exc}",
        ) from exc


@router.get("/{owner}/{repo}/{pr_number}", response_model=PRAnalysisRecord)
def get_pr_analysis(owner: str, repo: str, pr_number: int) -> PRAnalysisRecord:
    """Retrieve the current active or latest analysis record for a Pull Request."""
    record = scan_db.get_latest_pr_analysis(owner, repo, pr_number)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis record found for PR #{pr_number} in {owner}/{repo}",
        )
    return record


@router.get("/{owner}/{repo}/{pr_number}/comparison", response_model=ScanComparisonResult)
def get_pr_comparison(owner: str, repo: str, pr_number: int) -> ScanComparisonResult:
    """Retrieve the full deterministic ScanComparisonResult for a Pull Request."""
    record = scan_db.get_latest_pr_analysis(owner, repo, pr_number)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis record found for PR #{pr_number} in {owner}/{repo}",
        )

    comparison = scan_db.get_pr_comparison(record.id)
    if not comparison:
        # If comparison was not pre-cached, but both scans exist, compute on-demand
        if record.base_scan_id and record.head_scan_id:
            from app.services.repository_service import repository_service

            base_scan = repository_service.get_scan(record.base_scan_id)
            head_scan = repository_service.get_scan(record.head_scan_id)
            if base_scan and head_scan:
                return github_workflow_service.comp_svc.compare_scans(head_scan, base_scan)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Comparison result unavailable for PR #{pr_number}",
        )
    return comparison


@router.get("/{owner}/{repo}", response_model=list[PRAnalysisRecord])
def list_pr_analyses(
    owner: str,
    repo: str,
    limit: int = Query(20, ge=1, le=100),
) -> list[PRAnalysisRecord]:
    """List recent Pull Request analysis records for a repository."""
    return scan_db.list_pr_analyses_for_repo(owner, repo, limit=limit)
