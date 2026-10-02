"""Policy Engine REST API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.policy.models import PolicyConfig, PolicyEvaluation
from app.policy.parser import PolicyConfigurationError, parse_policy_dict
from app.policy.service import policy_service

router = APIRouter(prefix="/policies", tags=["Policies"])


class PolicyValidationResponse(BaseModel):
    """Validation response indicating whether a policy payload is valid."""

    valid: bool
    policy: PolicyConfig | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)


@router.get("", response_model=list[PolicyConfig])
def list_policies() -> list[PolicyConfig]:
    """List available organizational debt policies."""
    return [policy_service.get_default_policy()]


@router.get("/default", response_model=PolicyConfig)
def get_default_policy() -> PolicyConfig:
    """Retrieve the standard built-in Entropy policy."""
    return policy_service.get_default_policy()


@router.post("/validate", response_model=PolicyValidationResponse)
def validate_policy(payload: dict[str, Any]) -> PolicyValidationResponse:
    """Validate a declarative policy configuration against the strict Policy schema."""
    try:
        policy = parse_policy_dict(payload)
        return PolicyValidationResponse(valid=True, policy=policy, errors=[])
    except PolicyConfigurationError as exc:
        return PolicyValidationResponse(valid=False, policy=None, errors=exc.errors)


@router.post("/scans/{scan_id}/evaluate", response_model=PolicyEvaluation)
def evaluate_scan_policy(
    scan_id: str,
    custom_policy: PolicyConfig | None = None,
) -> PolicyEvaluation:
    """Evaluate a standalone repository scan against a configured or default policy."""
    try:
        return policy_service.evaluate_scan(scan_id=scan_id, policy=custom_policy)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/scans/{current_scan_id}/compare/{previous_scan_id}/evaluate",
    response_model=PolicyEvaluation,
)
def evaluate_comparison_policy(
    current_scan_id: str,
    previous_scan_id: str,
    custom_policy: PolicyConfig | None = None,
) -> PolicyEvaluation:
    """Evaluate a scan-to-scan comparison against a configured or default policy."""
    try:
        return policy_service.evaluate_comparison(
            current_scan_id=current_scan_id,
            previous_scan_id=previous_scan_id,
            policy=custom_policy,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get("/github/prs/{analysis_id}/policy", response_model=PolicyEvaluation)
def get_pr_analysis_policy(analysis_id: str) -> PolicyEvaluation:
    """Retrieve or compute the PolicyEvaluation result for a Pull Request analysis."""
    # Check if already evaluated and persisted
    cached = policy_service.db.get_pr_policy(analysis_id)
    if cached:
        return cached

    # Compute if not cached
    try:
        return policy_service.evaluate_pr_analysis(analysis_id=analysis_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
