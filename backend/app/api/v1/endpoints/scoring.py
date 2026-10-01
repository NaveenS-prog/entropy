"""API endpoints for Entropy Debt Score computation and retrieval."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.core.errors import RepositoryNotFoundError
from app.models.domain.scoring import DebtScoreResult
from app.scoring.service import scoring_service

router = APIRouter()


@router.get("/{scan_id}/score", response_model=DebtScoreResult)
def get_scan_score(
    scan_id: str,
    force_recalculate: bool = Query(
        default=False,
        description="Whether to force re-computation of the score from fresh findings",
    ),
) -> DebtScoreResult:
    """Retrieve the deterministic Entropy Debt Score for a scan.

    Returns the comprehensive 0-100 debt score, score band (VERY_LOW to VERY_HIGH),
    severity breakdown, analyzed vs not_analyzed category breakdowns, and audit trail.

    The score represents architectural/security debt detected by Entropy's static rules.
    It does not measure vulnerability probability or AI authorship.
    """
    try:
        return scoring_service.calculate_scan_score(
            scan_id=scan_id,
            force_recalculate=force_recalculate,
        )
    except RepositoryNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scoring computation failed: {err}",
        ) from err


@router.get("/{scan_id}/score/breakdown")
def get_scan_score_breakdown(
    scan_id: str,
) -> dict:
    """Retrieve detailed category-by-category and rule-by-rule score breakdown."""
    try:
        score_result = scoring_service.calculate_scan_score(scan_id=scan_id)
        return {
            "scan_id": scan_id,
            "entropy_score": score_result.total_score,
            "tier": score_result.tier.value,
            "tier_label": score_result.tier.label,
            "status": score_result.status.value,
            "analyzed_categories": [c.value for c in score_result.analyzed_categories],
            "categories": {
                cat.value: breakdown.model_dump()
                for cat, breakdown in score_result.category_scores.items()
            },
            "severity_breakdown": {
                s.value: count for s, count in score_result.severity_breakdown.items()
            },
            "top_contributing_rules": [
                r.model_dump() for r in score_result.top_contributing_rules
            ],
            "normalization": (
                score_result.normalization.model_dump()
                if score_result.normalization
                else None
            ),
            "formula_summary": score_result.formula_summary,
            "audit_trail": score_result.audit_trail,
            "disclaimer": score_result.disclaimer,
        }
    except RepositoryNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
