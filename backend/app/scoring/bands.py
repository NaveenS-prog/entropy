"""Entropy Score Band Classification and Clamping.

Official Score Bands:
0  – 20: VERY_LOW
21 – 40: LOW
41 – 60: MODERATE
61 – 80: HIGH
81 – 100: VERY_HIGH

The API and scoring engine must never produce or expose an out-of-bounds score (< 0 or > 100).
"""

from __future__ import annotations

from app.models.domain.enums import DebtScoreTier

# Explicit boundary definitions
BAND_RANGES: dict[DebtScoreTier, tuple[int, int]] = {
    DebtScoreTier.VERY_LOW: (0, 20),
    DebtScoreTier.LOW: (21, 40),
    DebtScoreTier.MODERATE: (41, 60),
    DebtScoreTier.HIGH: (61, 80),
    DebtScoreTier.VERY_HIGH: (81, 100),
}


def clamp_score(score: float | int) -> int:
    """Clamp score strictly to integer range [0, 100]."""
    rounded = int(round(score))
    return max(0, min(100, rounded))


def classify_score_band(score: float | int) -> DebtScoreTier:
    """Classify an integer or float score into an official Entropy Debt Tier.

    Boundary handling:
    - Values < 0 are clamped to 0 (VERY_LOW)
    - 0  <= score <= 20: VERY_LOW
    - 21 <= score <= 40: LOW
    - 41 <= score <= 60: MODERATE
    - 61 <= score <= 80: HIGH
    - 81 <= score <= 100: VERY_HIGH
    - Values > 100 are clamped to 100 (VERY_HIGH)
    """
    clamped = clamp_score(score)
    if clamped <= 20:
        return DebtScoreTier.VERY_LOW
    elif clamped <= 40:
        return DebtScoreTier.LOW
    elif clamped <= 60:
        return DebtScoreTier.MODERATE
    elif clamped <= 80:
        return DebtScoreTier.HIGH
    else:
        return DebtScoreTier.VERY_HIGH


def get_band_description(tier: DebtScoreTier) -> str:
    """Provide official product interpretation for a given score tier."""
    descriptions = {
        DebtScoreTier.VERY_LOW: "Pristine or near-pristine codebase; highly consistent architecture.",
        DebtScoreTier.LOW: "Minor structural duplication or localized inconsistent error handling.",
        DebtScoreTier.MODERATE: "Noticeable accumulation of silent debt; architectural patterns need attention.",
        DebtScoreTier.HIGH: "Substantial fragmentation, swallowed errors, or missing security boundaries.",
        DebtScoreTier.VERY_HIGH: "Severe architectural risk; elevated probability of hidden failures and bugs.",
    }
    return descriptions.get(tier, "Unknown debt tier.")
