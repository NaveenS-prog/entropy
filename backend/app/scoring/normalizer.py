"""Normalization logic for Entropy Scoring.

Prevents repository size from producing misleading scores while ensuring:
1. Determinism: pure arithmetic with zero random or non-reproducible state.
2. Monotonicity: adding an authentic finding to an identical repository never decreases the score.
3. Boundedness: category scores are strictly bounded in [0.0, 100.0].
4. Scale Resistance: prevents trivial score inflation for massive repositories
   while preventing false innocence in tiny codebases.

Mathematical Model:
-------------------
1. Raw Penalty:
   Raw_Penalty = Σ ( Severity_Weight(f) × Confidence_Weight(f) )

2. Scale Factor (Sublinear LOC Damping):
   Scale_Factor = max( 1.0, sqrt( max(total_loc, MIN_LOC_FLOOR) / BASELINE_LOC ) )

3. Normalized Penalty:
   Normalized_Penalty = Raw_Penalty / Scale_Factor

4. Asymptotic Saturation (Category Score 0-100):
   Category_Score = 100.0 × ( 1.0 - exp( -Normalized_Penalty / SATURATION_FACTOR ) )
"""

from __future__ import annotations

import math
from typing import NamedTuple

from app.scoring.weights import BASELINE_LOC, MIN_LOC_FLOOR, SATURATION_FACTOR


class NormalizationResult(NamedTuple):
    """Container for intermediate normalization metrics for auditability."""

    raw_penalty: float
    scale_factor: float
    normalized_penalty: float
    category_score: float
    kloc: float
    weighted_debt_density: float
    formula: str


class ScoreNormalizer:
    """Calculates transparent, bounded, monotonic category normalization."""

    @staticmethod
    def calculate_scale_factor(total_loc: int) -> float:
        """Calculate sublinear scale damping factor based on repository LOC."""
        effective_loc = max(total_loc, MIN_LOC_FLOOR)
        if effective_loc <= BASELINE_LOC:
            return 1.0
        return math.sqrt(effective_loc / BASELINE_LOC)

    @classmethod
    def normalize_category_penalty(
        cls,
        raw_penalty: float,
        total_loc: int = 0,
        analyzed_files: int = 0,
    ) -> NormalizationResult:
        """Normalize raw finding penalties into a bounded 0-100 score."""
        if raw_penalty <= 0.0:
            return NormalizationResult(
                raw_penalty=0.0,
                scale_factor=1.0,
                normalized_penalty=0.0,
                category_score=0.0,
                kloc=round(max(total_loc, 0) / 1000.0, 3),
                weighted_debt_density=0.0,
                formula="Score = 0.0 (Zero raw penalty)",
            )

        scale_factor = cls.calculate_scale_factor(total_loc)
        normalized_penalty = raw_penalty / scale_factor

        # Asymptotic curve: 100 * (1 - e^(-norm / K))
        score = 100.0 * (1.0 - math.exp(-normalized_penalty / SATURATION_FACTOR))
        score = min(100.0, max(0.0, score))

        effective_kloc = max(0.1, total_loc / 1000.0) if total_loc > 0 else 0.1
        wdd = raw_penalty / effective_kloc

        formula = (
            f"Normalized_Penalty ({normalized_penalty:.2f}) = "
            f"Raw_Penalty ({raw_penalty:.2f}) / Scale_Factor ({scale_factor:.2f}) [LOC: {total_loc}]; "
            f"Category_Score ({score:.1f}) = 100 × (1 - exp(-{normalized_penalty:.2f} / {SATURATION_FACTOR}))"
        )

        return NormalizationResult(
            raw_penalty=round(raw_penalty, 3),
            scale_factor=round(scale_factor, 3),
            normalized_penalty=round(normalized_penalty, 3),
            category_score=round(score, 1),
            kloc=round(max(total_loc, 0) / 1000.0, 3),
            weighted_debt_density=round(wdd, 2),
            formula=formula,
        )


normalizer = ScoreNormalizer()
