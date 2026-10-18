"""Domain models for Entropy Debt scoring.

Re-exports models from app.scoring.models for clean architecture and backwards compatibility.
"""

from app.scoring.models import (
    CategoryAnalysisStatus,
    CategoryCoverage,
    CategoryScoreBreakdown,
    DebtScoreResult,
    NormalizationMetrics,
    RuleContribution,
    ScoringCoverage,
    ScoringStatus,
)

__all__ = [
    "CategoryAnalysisStatus",
    "CategoryCoverage",
    "CategoryScoreBreakdown",
    "DebtScoreResult",
    "NormalizationMetrics",
    "RuleContribution",
    "ScoringCoverage",
    "ScoringStatus",
]

