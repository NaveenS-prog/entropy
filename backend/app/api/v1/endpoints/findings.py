"""Endpoints for querying architectural debt findings and explanations."""

from fastapi import APIRouter, HTTPException, Query, status

from app.ai.explainer import (
    DeterministicBaselineExplainer,
    FindingExplanation,
    RefactoringSuggestion,
)
from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import Finding
from app.services.analysis_service import analysis_service

router = APIRouter()
explainer = DeterministicBaselineExplainer()


@router.get("/{scan_id}/findings", response_model=list[Finding])
def get_findings_for_scan(
    scan_id: str,
    category: DebtCategory | None = Query(default=None, description="Filter by debt category"),
    severity: Severity | None = Query(default=None, description="Filter by finding severity"),
    rule_id: str | None = Query(default=None, description="Filter by specific rule ID (e.g. ENT-ERR-001)"),
    file: str | None = Query(default=None, description="Filter by file path substring"),
    confidence: Confidence | None = Query(default=None, description="Filter by confidence"),
) -> list[Finding]:
    """Retrieve and filter deterministic architectural debt findings for a scan."""
    try:
        results = analysis_service.analyze_scan(
            scan_id=scan_id,
            category=category,
            severity=severity,
            rule_id=rule_id,
            file_filter=file,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    if confidence:
        results = [f for f in results if f.confidence == confidence]

    return results


@router.get("/{scan_id}/findings/{finding_id}", response_model=Finding)
def get_single_finding(scan_id: str, finding_id: str) -> Finding:
    """Retrieve a single finding by ID."""
    finding = analysis_service.get_finding(scan_id, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )
    return finding


@router.get("/{scan_id}/findings/{finding_id}/explain", response_model=FindingExplanation)
def explain_finding(scan_id: str, finding_id: str) -> FindingExplanation:
    """Retrieve a grounded architectural explanation for a finding."""
    finding = analysis_service.get_finding(scan_id, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )

    return explainer.explain(finding)


@router.get("/{scan_id}/findings/{finding_id}/refactor", response_model=RefactoringSuggestion)
def suggest_refactor(scan_id: str, finding_id: str) -> RefactoringSuggestion:
    """Retrieve an architectural refactoring suggestion for a finding."""
    finding = analysis_service.get_finding(scan_id, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )

    return explainer.suggest_refactor(finding)
