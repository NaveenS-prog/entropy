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
# Relative weights are computed dynamically across active analyzed categories with language support.
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
# Normalization & Saturation Constants (Density-Based Scoring)
# =============================================================================
# Density saturation constant K for asymptotic category curve:
# Category_Score = 100 * (1 - e^(-Weighted_Debt_Density / DENSITY_SATURATION_FACTOR))
DENSITY_SATURATION_FACTOR: float = 40.0

# Legacy alias for backward compatibility
SATURATION_FACTOR: float = DENSITY_SATURATION_FACTOR

# Base LOC threshold below which repository scale factor remains 1.0 (legacy alias)
BASELINE_LOC: int = 500

# Minimum LOC considered for KLOC density calculation to prevent division by zero or explosion on tiny repos
MIN_LOC_FLOOR: int = 200

# Sensitive terms whose presence in route paths or symbols escalates debt severity
SENSITIVE_ROUTE_TERMS: set[str] = {
    "admin",
    "payment",
    "refund",
    "delete",
    "export",
    "user",
    "token",
}

# Intentionally public endpoint terms (configurable)
# When an endpoint path or handler name matches any of these terms, it is treated as intentionally public.
INTENTIONALLY_PUBLIC_ENDPOINT_TERMS: set[str] = {
    "login",
    "signin",
    "signup",
    "register",
    "logout",
    "token",
    "refresh",
    "callback",
    "oauth",
    "password-reset",
    "forgot-password",
    "reset-password",
    "verify-email",
    "health",
    "healthz",
    "ping",
    "status",
    "docs",
    "openapi",
    "metrics",
}

# Sensitive data indicators in response models or bodies
SENSITIVE_DATA_TERMS: set[str] = {
    "password",
    "passwd",
    "secret",
    "hash",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
    "private_key",
    "credentials",
    "api_key",
    "token",
    "auth",
    "user",
    "admin",
    "payment",
    "refund",
    "account",
    "delete",
    "privilege",
    "permission",
    "role",
    "charge",
    "amount",
}


def is_intentionally_public_endpoint(
    route_path: str | None,
    handler_name: str | None,
    terms: set[str] | None = None,
) -> bool:
    """Check if a route path or handler name matches configured intentionally public terms."""
    import re

    check_terms = terms if terms is not None else INTENTIONALLY_PUBLIC_ENDPOINT_TERMS
    path_lower = (route_path or "").lower()

    # Only treat handler_name as a name if it's an identifier or simple name (not a code snippet/arrow function)
    clean_handler = ""
    if handler_name:
        h_str = handler_name.strip()
        if re.match(r"^[a-zA-Z_$][a-zA-Z0-9_$-]*$", h_str):
            clean_handler = h_str.lower()

    path_tokens = set(re.findall(r"[a-z0-9]+", path_lower))
    handler_tokens = set(re.findall(r"[a-z0-9]+", clean_handler)) if clean_handler else set()
    combined_tokens = path_tokens | handler_tokens

    for term in check_terms:
        term_clean = term.lower()
        if "-" in term_clean or "_" in term_clean:
            term_alt = term_clean.replace("-", "_")
            term_hyphen = term_clean.replace("_", "-")
            if (
                term_clean in path_lower
                or term_alt in path_lower
                or term_hyphen in path_lower
                or (clean_handler and (
                    term_clean in clean_handler
                    or term_alt in clean_handler
                    or term_hyphen in clean_handler
                ))
            ):
                return True
        else:
            if term_clean in combined_tokens:
                return True
    return False


def drop_severity_one_level(severity: Severity) -> Severity:
    """Drop finding severity by one level (e.g. CRITICAL -> HIGH, HIGH -> MEDIUM, MEDIUM -> LOW)."""
    mapping = {
        Severity.CRITICAL: Severity.HIGH,
        Severity.HIGH: Severity.MEDIUM,
        Severity.MEDIUM: Severity.LOW,
        Severity.LOW: Severity.INFO,
        Severity.INFO: Severity.INFO,
    }
    return mapping.get(severity, severity)


# =============================================================================
# Severity Floor Constants
# =============================================================================
# High-confidence severe findings establish a lower bound on the overall score
# and tier so that critical defects are never diluted by large codebase volume.
SEVERITY_FLOOR_MODERATE_SCORE: int = 41    # Minimum score for MODERATE tier (>= 1 HIGH finding with HIGH confidence)
SEVERITY_FLOOR_HIGH_SCORE: int = 61        # Minimum score for HIGH tier (>= 1 CRITICAL finding with HIGH confidence)
SEVERITY_FLOOR_VERY_HIGH_SCORE: int = 81   # Minimum score for VERY_HIGH tier (>= 2 CRITICAL findings with HIGH confidence)

