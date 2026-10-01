"""Pydantic schemas and domain models for the Entropy Scoring Engine."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, computed_field

from app.models.domain.enums import DebtCategory, DebtScoreTier, Severity


class ScoringStatus(StrEnum):
    """Lifecycle state of scoring computation."""

    AVAILABLE = "available"
    PENDING = "pending"
    NOT_ANALYZABLE = "not_analyzable"
    FAILED = "failed"


class CategoryAnalysisStatus(StrEnum):
    """Status indicating whether a debt category is implemented and analyzed."""

    ANALYZED = "analyzed"
    NOT_ANALYZED = "not_analyzed"


class RuleContribution(BaseModel):
    """Contribution of a specific static analysis rule to debt score."""

    rule_id: str = Field(..., description="Unique rule identifier (e.g. ENT-ERR-001)")
    rule_title: str = Field(..., description="Human-readable title of rule")
    finding_count: int = Field(default=0, ge=0, description="Total findings triggered by this rule")
    weighted_points: float = Field(default=0.0, ge=0.0, description="Cumulative weighted penalty points")


class CategoryScoreBreakdown(BaseModel):
    """Granular debt score breakdown for a specific category."""

    category: DebtCategory = Field(..., description="The debt category")
    status: CategoryAnalysisStatus = Field(
        default=CategoryAnalysisStatus.ANALYZED,
        description="Whether this category was analyzed or is awaiting implementation",
    )
    score: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Category debt score (0-100), or null if not analyzed",
    )
    finding_count: int = Field(default=0, ge=0, description="Total findings in this category")
    severity_counts: dict[Severity, int] = Field(
        default_factory=lambda: {s: 0 for s in Severity},
        description="Counts of findings by severity",
    )
    weight: float = Field(..., ge=0.0, description="Category relative weight in aggregate score")
    weighted_score: float = Field(default=0.0, description="Contribution to overall score")
    raw_deduction: float = Field(default=0.0, description="Raw cumulative penalty points")
    normalized_penalty: float = Field(default=0.0, description="Scale-normalized penalty points")
    explanation: str = Field(..., description="Human-readable explanation of how this score was reached")
    top_rules: list[RuleContribution] = Field(default_factory=list, description="Top contributing rules")


class NormalizationMetrics(BaseModel):
    """Repository scale metrics utilized during score normalization."""

    total_loc: int = Field(..., description="Total source lines of code analyzed")
    analyzed_files: int = Field(..., description="Total source files analyzed")
    kloc: float = Field(..., description="Source code in thousands of lines (KLOC)")
    scale_factor: float = Field(..., description="Sublinear damping scale factor applied")
    formula: str = Field(..., description="Mathematical description of normalization step")


class DebtScoreResult(BaseModel):
    """Comprehensive, explainable Entropy Debt Score result.

    The Entropy Score represents architectural and security debt detected by Entropy's
    static-analysis rules. It does not measure vulnerability exploitability or AI authorship.
    """

    total_score: int = Field(..., ge=0, le=100, description="Final aggregated debt score (0-100)")
    tier: DebtScoreTier = Field(..., description="Product interpretation category")
    status: ScoringStatus = Field(default=ScoringStatus.AVAILABLE, description="Scoring availability status")
    analyzed_categories: list[DebtCategory] = Field(
        default_factory=list,
        description="Categories currently implemented and contributing to score",
    )
    category_scores: dict[DebtCategory, CategoryScoreBreakdown] = Field(
        ...,
        description="Individual breakdowns for each debt category",
    )
    total_findings: int = Field(..., ge=0, description="Total findings across all analyzed categories")
    total_loc: int = Field(..., ge=0, description="Total lines of source code scanned")
    analyzed_files: int = Field(..., ge=0, description="Number of files parsed and analyzed")
    skipped_files: int = Field(default=0, ge=0, description="Files skipped during scan")
    severity_breakdown: dict[Severity, int] = Field(
        default_factory=lambda: {s: 0 for s in Severity},
        description="Aggregate count of findings by severity",
    )
    top_contributing_rules: list[RuleContribution] = Field(
        default_factory=list,
        description="Highest penalty rules across all analyzed categories",
    )
    normalization: NormalizationMetrics | None = Field(
        default=None,
        description="Scale normalization metadata",
    )
    formula_summary: str = Field(
        ...,
        description="Mathematical formula used for auditability and transparency",
    )
    audit_trail: list[str] = Field(
        default_factory=list,
        description="Step-by-step audit logs verifying deterministic score calculation",
    )
    is_explainable: bool = Field(
        default=True,
        description="Confirms that every metric is derived from actual static analysis",
    )
    disclaimer: str = Field(
        default=(
            "The Entropy Score is an indicator of architectural/security debt detected by Entropy's "
            "static-analysis rules. It is not a vulnerability probability and does not measure AI authorship."
        ),
        description="Legal and product transparency disclaimer",
    )

    @computed_field
    @property
    def entropy_score(self) -> int:
        """Alias for total_score per Phase 4 specification."""
        return self.total_score

    @computed_field
    @property
    def band(self) -> DebtScoreTier:
        """Alias for tier per Phase 4 specification."""
        return self.tier

