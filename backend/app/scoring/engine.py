"""Backward-compatible ScoringEngine adapter wrapping EntropyScorer."""

from __future__ import annotations

from app.models.domain.enums import DebtCategory
from app.models.domain.finding import Finding
from app.scoring.entropy_scorer import EntropyScorer, entropy_scorer
from app.scoring.models import DebtScoreResult


class ScoringEngine:
    """Adapter maintaining backward compatibility with prototype imports while invoking EntropyScorer."""

    def __init__(self, scorer: EntropyScorer | None = None) -> None:
        self.scorer = scorer or entropy_scorer

    def calculate_score(
        self,
        findings: list[Finding],
        total_loc: int = 0,
        analyzed_files: int = 0,
        skipped_files: int = 0,
        analyzed_categories: set[DebtCategory] | None = None,
    ) -> DebtScoreResult:
        """Calculate the comprehensive Entropy score."""
        return self.scorer.calculate_score(
            findings=findings,
            total_loc=total_loc,
            analyzed_files=analyzed_files,
            skipped_files=skipped_files,
            analyzed_categories=analyzed_categories,
        )


scoring_engine = ScoringEngine()
