"""Domain models for Silent Security Debt scoring."""

from pydantic import BaseModel, Field

from app.models.domain.enums import DebtCategory, DebtScoreTier, Severity


class CategoryScoreBreakdown(BaseModel):
    """Granular debt score breakdown for a specific debt category."""

    category: DebtCategory = Field(..., description="The debt category")
    score: float = Field(..., ge=0.0, le=100.0, description="Category debt score (0-100)")
    finding_count: int = Field(default=0, ge=0, description="Total findings in this category")
    severity_counts: dict[Severity, int] = Field(
        default_factory=lambda: {s: 0 for s in Severity},
        description="Counts of findings by severity",
    )
    weight: float = Field(..., ge=0.0, description="Category relative weight in aggregate score")
    weighted_score: float = Field(..., description="Score contribution to overall total")
    raw_deduction: float = Field(..., description="Raw cumulative penalty before normalization")
    explanation: str = Field(..., description="Human-readable explanation of how this score was reached")


class DebtScoreResult(BaseModel):
    """Comprehensive, explainable Silent Security Debt Score result.

    Range: 0-100
    0-20: Very Low Debt
    21-40: Low Debt
    41-60: Moderate Debt
    61-80: High Debt
    81-100: Very High Debt
    """

    total_score: int = Field(..., ge=0, le=100, description="Final aggregated debt score (0-100)")
    tier: DebtScoreTier = Field(..., description="Product interpretation category")
    category_scores: dict[DebtCategory, CategoryScoreBreakdown] = Field(
        ...,
        description="Individual breakdowns for each analysis category",
    )
    total_findings: int = Field(..., ge=0, description="Total findings across all categories")
    total_loc: int = Field(..., ge=0, description="Total lines of source code scanned")
    analyzed_files: int = Field(..., ge=0, description="Number of files parsed and analyzed")
    skipped_files: int = Field(default=0, ge=0, description="Files skipped (unsupported/binary)")
    formula_summary: str = Field(
        ...,
        description="Mathematical formula used for transparency and auditability",
    )
    audit_trail: list[str] = Field(
        default_factory=list,
        description="Step-by-step audit logs verifying deterministic score calculation",
    )
    is_explainable: bool = Field(
        default=True,
        description="Confirms that every metric is derived from actual static analysis",
    )
