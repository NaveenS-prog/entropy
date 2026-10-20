"""Normalization logic for Entropy Scoring.

Prevents repository size from producing misleading scores while ensuring:
1. Determinism: pure arithmetic with zero random or non-reproducible state.
2. Monotonicity: adding an authentic finding to an identical repository never decreases the score.
3. Boundedness: category scores are strictly bounded in [0.0, 100.0].
4. Density Invariance: identical defect density (defects per KLOC) yields identical scores
   regardless of whether codebase is 500 LOC or 500,000 LOC.
5. Minimum Floor: protects tiny repositories from mathematical explosion.

Mathematical Model:
-------------------
1. Raw Penalty:
   Raw_Penalty = Σ ( Severity_Weight(f) × Confidence_Weight(f) )

2. Effective Codebase Size (KLOC with Floor):
   Effective_LOC = max(total_loc, MIN_LOC_FLOOR)
   KLOC = Effective_LOC / 1000.0

3. Weighted Debt Density:
   Weighted_Debt_Density = Raw_Penalty / KLOC

4. Asymptotic Saturation (Category Score 0-100):
   Category_Score = 100.0 × ( 1.0 - exp( -Weighted_Debt_Density / DENSITY_SATURATION_FACTOR ) )
"""

from __future__ import annotations

import math
from typing import NamedTuple

from app.scoring.weights import DENSITY_SATURATION_FACTOR, MIN_LOC_FLOOR


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
        """Calculate KLOC scale factor based on repository LOC with minimum floor."""
        effective_loc = max(total_loc, MIN_LOC_FLOOR)
        return effective_loc / 1000.0

    @classmethod
    def normalize_category_penalty(
        cls,
        raw_penalty: float,
        total_loc: int = 0,
    ) -> NormalizationResult:
        """Normalize raw finding penalties into a bounded 0-100 score via debt density."""
        effective_loc = max(total_loc, MIN_LOC_FLOOR)
        kloc = effective_loc / 1000.0

        if raw_penalty <= 0.0:
            return NormalizationResult(
                raw_penalty=0.0,
                scale_factor=round(kloc, 3),
                normalized_penalty=0.0,
                category_score=0.0,
                kloc=round(kloc, 3),
                weighted_debt_density=0.0,
                formula=f"Score = 0.0 (Zero raw penalty; KLOC: {kloc:.3f})",
            )

        weighted_debt_density = raw_penalty / kloc

        # Asymptotic curve on density: 100 * (1 - e^(-density / K))
        score = 100.0 * (1.0 - math.exp(-weighted_debt_density / DENSITY_SATURATION_FACTOR))
        score = min(100.0, max(0.0, score))

        formula = (
            f"Effective_LOC = max(LOC={total_loc}, FLOOR={MIN_LOC_FLOOR}) = {effective_loc}; "
            f"KLOC = {kloc:.3f}; "
            f"Weighted_Debt_Density ({weighted_debt_density:.2f}) = Raw_Penalty ({raw_penalty:.2f}) / KLOC ({kloc:.3f}); "
            f"Category_Score ({score:.1f}) = 100 × (1 - exp(-{weighted_debt_density:.2f} / {DENSITY_SATURATION_FACTOR}))"
        )

        return NormalizationResult(
            raw_penalty=round(raw_penalty, 3),
            scale_factor=round(kloc, 3),
            normalized_penalty=round(weighted_debt_density, 3),
            category_score=round(score, 1),
            kloc=round(kloc, 3),
            weighted_debt_density=round(weighted_debt_density, 2),
            formula=formula,
        )


normalizer = ScoreNormalizer()
