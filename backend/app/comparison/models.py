"""Domain models for scan comparison, finding lifecycle, score deltas, and trends."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from app.models.domain.enums import Confidence, DebtCategory, DebtScoreTier, Severity


class FindingLifecycleStatus(StrEnum):
    """Lifecycle classification of a finding between two scans."""

    NEW = "new"  # Present in current scan, absent in previous scan
    RESOLVED = "resolved"  # Present in previous scan, no longer detected in current scan
    PERSISTENT = "persistent"  # Present in both previous and current scans


class ComparisonFindingItem(BaseModel):
    """Finding item within a comparison lifecycle context."""

    finding_id: str
    fingerprint: str
    category: DebtCategory
    rule_id: str
    severity: Severity
    confidence: Confidence
    file: str
    line_start: int
    line_end: int
    symbol: str | None = None
    title: str
    description: str
    lifecycle: FindingLifecycleStatus
    resolution_status: str | None = Field(
        default=None,
        description="Status description (e.g. 'No longer detected since previous scan')",
    )
    first_seen_scan_id: str | None = None
    last_seen_scan_id: str | None = None
    seen_in_scans_count: int | None = None


class ScoreComparison(BaseModel):
    """Overall score difference between previous and current scans."""

    previous_score: int | None = None
    current_score: int | None = None
    score_delta: int | None = None
    previous_band: DebtScoreTier | None = None
    current_band: DebtScoreTier | None = None
    direction: str = Field(
        ...,
        description="'increased' (debt increased/worse), 'decreased' (debt reduced/improved), or 'unchanged'",
    )
    explanation: str = Field(..., description="Neutral explanation of the score movement")


class CategoryComparison(BaseModel):
    """Category-level score and finding count comparison."""

    category: DebtCategory
    category_name: str
    previous_score: float | None = None
    current_score: float | None = None
    score_delta: float | None = None
    previous_status: str = Field(..., description="'analyzed' or 'not_analyzed'")
    current_status: str = Field(..., description="'analyzed' or 'not_analyzed'")
    previous_finding_count: int = 0
    current_finding_count: int = 0
    finding_count_delta: int = 0


class RuleComparison(BaseModel):
    """Rule-level finding count comparison."""

    rule_id: str
    category: DebtCategory
    previous_count: int = 0
    current_count: int = 0
    delta: int = 0


class ComparisonSummary(BaseModel):
    """Top-level high-level comparison metrics summary."""

    repository_id: str
    repo_name: str
    previous_scan_id: str
    current_scan_id: str
    previous_timestamp: datetime
    current_timestamp: datetime
    previous_commit: str | None = None
    current_commit: str | None = None
    previous_score: int | None = None
    current_score: int | None = None
    score_delta: int | None = None
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    persistent_findings_count: int = 0
    total_current_findings: int = 0


class ScanComparisonResult(BaseModel):
    """Complete deterministic scan-to-scan comparison result."""

    summary: ComparisonSummary
    score_comparison: ScoreComparison
    category_comparisons: dict[str, CategoryComparison]
    rule_comparisons: list[RuleComparison]
    new_findings: list[ComparisonFindingItem]
    resolved_findings: list[ComparisonFindingItem]
    persistent_findings: list[ComparisonFindingItem]


class TrendPoint(BaseModel):
    """Individual data point in a chronological score trend."""

    scan_id: str
    timestamp: datetime
    score: int
    score_band: DebtScoreTier
    finding_count: int
    commit_hash: str | None = None
    branch: str | None = None


class CategoryTrendPoint(BaseModel):
    """Individual data point for a category score trend."""

    scan_id: str
    timestamp: datetime
    score: float | None = None
    status: str = "analyzed"


class RepositoryTrendResponse(BaseModel):
    """Chronological debt score progression for a repository."""

    repository_id: str
    repo_name: str
    points: list[TrendPoint]
    category_trends: dict[str, list[CategoryTrendPoint]] = Field(default_factory=dict)
    total_scans: int
    message: str | None = None
