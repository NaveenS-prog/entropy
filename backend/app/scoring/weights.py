"""Centralized weights, constants, and calibration parameters for Entropy Scoring.

All severity weights, confidence multipliers, category weights, and normalization
scaling factors are centralized in this module to avoid magic numbers.

The Entropy Score represents architectural and security debt detected by Entropy's
static-analysis rules. It does not measure vulnerability exploitability or AI authorship.
"""

from __future__ import annotations

from app.models.domain.enums import Confidence, DebtCategory, Severity

# =============================================================================
# Severity Weights (Accumulation Risk)
# =============================================================================
# Weights reflect the architectural and maintenance hazard of the defect:
# - CRITICAL (10.0): Catastrophic architectural degradation (e.g. system signal hijacking)
# - HIGH (7.0): Severe silent debt (e.g. swallowed exceptions without logging or re-raise)
# - MEDIUM (4.0): Substantial inconsistency (e.g. bare excepts, broad catch clauses)
# - LOW (1.0): Minor structural bad practice (e.g. generic falsy fallback returns)
# - INFO (0.0): Informational notice; does not penalize score
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}

# Legacy alias for backward compatibility
SEVERITY_POINTS = SEVERITY_WEIGHTS


# =============================================================================
# Confidence Multipliers (Detection Certainty)
# =============================================================================
# Multipliers scale raw severity points by static analyzer certainty:
# - HIGH (1.0): 100% deterministic AST match
# - MEDIUM (0.8): Context-dependent pattern match
# - LOW (0.5): Heuristic or potential false-positive dampening
CONFIDENCE_WEIGHTS: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.8,
    Confidence.LOW: 0.5,
}

# Legacy alias for backward compatibility
CONFIDENCE_MULTIPLIERS = CONFIDENCE_WEIGHTS


# =============================================================================
# Category Weights (Target 100% Architecture Distribution)
# =============================================================================
# Normalized distribution across the 7 Entropy debt categories.
# In Phase 4, only active categories (Error Handling Debt) contribute to the
# score; relative weights are computed dynamically across analyzed categories.
CATEGORY_WEIGHTS: dict[DebtCategory, float] = {
    DebtCategory.AUTHENTICATION_CONSISTENCY: 0.20,
    DebtCategory.AUTHORIZATION_CONSISTENCY: 0.20,
    DebtCategory.ERROR_HANDLING: 0.15,
    DebtCategory.INPUT_VALIDATION: 0.15,
    DebtCategory.LOGGING_AND_SECRETS: 0.15,
    DebtCategory.ARCHITECTURAL_CONSISTENCY: 0.10,
    DebtCategory.CODE_DUPLICATION: 0.05,
}


# =============================================================================
# Normalization & Saturation Constants
# =============================================================================
# Saturation constant K for asymptotic category curve:
# Category_Score = 100 * (1 - e^(-Normalized_Penalty / SATURATION_FACTOR))
SATURATION_FACTOR: float = 25.0

# Base LOC threshold below which repository scale factor remains 1.0
BASELINE_LOC: int = 500

# Minimum LOC considered for KLOC density calculation to prevent division by zero
MIN_LOC_FLOOR: int = 100
