"""Scan comparison and trend intelligence package for Entropy Phase 10."""

from app.comparison.models import (
    CategoryComparison,
    CategoryTrendPoint,
    ComparisonFindingItem,
    ComparisonSummary,
    FindingLifecycleStatus,
    RepositoryTrendResponse,
    RuleComparison,
    ScanComparisonResult,
    ScoreComparison,
    TrendPoint,
)
from app.comparison.service import ComparisonService, comparison_service

__all__ = [
    "CategoryComparison",
    "CategoryTrendPoint",
    "ComparisonFindingItem",
    "ComparisonService",
    "ComparisonSummary",
    "FindingLifecycleStatus",
    "RepositoryTrendResponse",
    "RuleComparison",
    "ScanComparisonResult",
    "ScoreComparison",
    "TrendPoint",
    "comparison_service",
]
