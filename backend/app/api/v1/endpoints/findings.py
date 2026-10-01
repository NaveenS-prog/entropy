"""Endpoints for querying findings and obtaining architectural explanations."""


from fastapi import APIRouter, HTTPException, Query, status

from app.ai.explainer import (
    DeterministicBaselineExplainer,
    FindingExplanation,
    RefactoringSuggestion,
)
from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import Finding
from app.services.scan_service import scan_service

router = APIRouter()
explainer = DeterministicBaselineExplainer()


@router.get("/{scan_id}/findings", response_model=list[Finding])
def get_findings_for_scan(
    scan_id: str,
    category: DebtCategory | None = Query(default=None, description="Filter by debt category"),
    severity: Severity | None = Query(default=None, description="Filter by finding severity"),
    confidence: Confidence | None = Query(default=None, description="Filter by confidence"),
    file: str | None = Query(default=None, description="Filter by file path substring"),
) -> list[Finding]:
    """Retrieve and filter findings from a specific scan."""
    scan = scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    results = scan.findings

    if category:
        results = [f for f in results if f.category == category]
    if severity:
        results = [f for f in results if f.severity == severity]
    if confidence:
        results = [f for f in results if f.confidence == confidence]
    if file:
        results = [f for f in results if file.lower() in f.file.lower()]

    return results


@router.get("/{scan_id}/findings/{finding_id}/explain", response_model=FindingExplanation)
def explain_finding(scan_id: str, finding_id: str) -> FindingExplanation:
    """Retrieve a grounded architectural explanation for a finding."""
    scan = scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    matching_finding = next((f for f in scan.findings if f.id == finding_id), None)
    if not matching_finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )

    return explainer.explain(matching_finding)


@router.get("/{scan_id}/findings/{finding_id}/refactor", response_model=RefactoringSuggestion)
def suggest_refactor(scan_id: str, finding_id: str) -> RefactoringSuggestion:
    """Retrieve an architectural refactoring suggestion for a finding."""
    scan = scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    matching_finding = next((f for f in scan.findings if f.id == finding_id), None)
    if not matching_finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in scan '{scan_id}'",
        )

    return explainer.suggest_refactor(matching_finding)
