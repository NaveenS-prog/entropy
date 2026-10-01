"""Scoring weights, constants, and calibration parameters."""

from app.models.domain.enums import Confidence, DebtCategory, Severity

# Weights assigned to each debt category (must sum to 1.0)
CATEGORY_WEIGHTS: dict[DebtCategory, float] = {
    DebtCategory.AUTHENTICATION_CONSISTENCY: 0.20,
    DebtCategory.AUTHORIZATION_CONSISTENCY: 0.20,
    DebtCategory.ERROR_HANDLING: 0.15,
    DebtCategory.INPUT_VALIDATION: 0.15,
    DebtCategory.LOGGING_AND_SECRETS: 0.15,
    DebtCategory.ARCHITECTURAL_CONSISTENCY: 0.10,
    DebtCategory.CODE_DUPLICATION: 0.05,
}

# Penalty points based on finding severity
SEVERITY_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 1.0,
    Severity.INFO: 0.25,
}

# Multiplier based on detection confidence
CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.8,
    Confidence.LOW: 0.5,
}

# Saturation scaling parameter for asymptotic category scoring
# Category Score = 100 * (1 - e^(-raw_penalty / SATURATION_FACTOR))
SATURATION_FACTOR: float = 20.0
