"""Centralized weights, constants, and calibration parameters for Entropy Scoring.

All severity weights, confidence multipliers, category weights, and normalization
scaling factors are centralized in this module to avoid magic numbers.

The Entropy Score represents architectural and security debt detected by Entropy's
static-analysis rules. It does not measure vulnerability exploitability or AI authorship.
"""

from __future__ import annotations

import math
import re

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
    "register-user",
    "create-user",
    "new-user",
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
# Severity Floor Constants & Named Triggers
# =============================================================================
# High-confidence severe findings establish a lower bound on the overall score
# and tier so that critical defects are never diluted by large codebase volume.
SEVERITY_FLOOR_MODERATE_SCORE: int = 41    # Minimum score for MODERATE tier (>= 1 HIGH finding with HIGH confidence)
SEVERITY_FLOOR_HIGH_SCORE: int = 61        # Minimum score for HIGH tier (>= 1 CRITICAL finding with HIGH confidence)
SEVERITY_FLOOR_VERY_HIGH_SCORE: int = 81   # Minimum score for VERY_HIGH tier (>= 2 CRITICAL findings with HIGH confidence)

SEVERITY_FLOOR_ADMIN_PATH_TERMS: set[str] = {"admin", "manage", "internal"}
SEVERITY_FLOOR_MUTATING_METHODS: set[str] = {"POST", "PUT", "DELETE", "PATCH"}
SEVERITY_FLOOR_CREDENTIAL_RULES: set[str] = {"ENT-LOG-002"}
SEVERITY_FLOOR_INJECTION_RULES: set[str] = {"ENT-INPUT-003", "ENT-INPUT-JS-001"}
SEVERITY_FLOOR_MIN_CREDENTIAL_CONFIDENCE_WEIGHT: float = 0.8


def is_severity_floor_trigger(finding: object) -> bool:
    """Check if a finding matches a named trigger permitted to establish a severity floor.

    Permitted named triggers per specification:
    1. Hardcoded credentials (rule ENT-LOG-002 with confidence >= 0.8).
    2. Unprotected mutating admin endpoint (ENT-AUTH-001 on POST/PUT/DELETE/PATCH with
       path containing admin/manage/internal and not in test/example).
    3. Confirmed unauthenticated SQLi or RCE sink (ENT-INPUT-003 or ENT-INPUT-JS-001).
    """
    sev = getattr(finding, "severity", None)
    if sev not in (Severity.CRITICAL, Severity.HIGH):
        return False

    rule_id = getattr(finding, "rule_id", "")

    # 1. Hardcoded credentials
    if rule_id in SEVERITY_FLOOR_CREDENTIAL_RULES:
        conf = getattr(finding, "confidence", None)
        conf_weight = CONFIDENCE_WEIGHTS.get(conf, 0.0) if hasattr(conf, "value") else 1.0
        return conf_weight >= SEVERITY_FLOOR_MIN_CREDENTIAL_CONFIDENCE_WEIGHT

    # 2. Unprotected mutating admin endpoint
    if rule_id == "ENT-AUTH-001":
        methods: set[str] = set()
        route_path = ""
        meta = getattr(finding, "metadata", None) or {}
        if meta:
            m = meta.get("http_methods")
            if isinstance(m, list):
                methods = {str(x).upper() for x in m}
            elif isinstance(m, str):
                methods = {m.upper()}
            route_path = str(meta.get("route_path", "")).lower()

        desc = getattr(finding, "description", "") or ""
        evidence_content = ""
        ev = getattr(finding, "evidence", None)
        if ev and hasattr(ev, "content") and ev.content:
            evidence_content = ev.content.lower()

        if not methods or not route_path:
            m_match = re.search(r"'(POST|PUT|DELETE|PATCH)\s+([^']+)'", desc, re.IGNORECASE)
            if m_match:
                methods.add(m_match.group(1).upper())
                route_path = m_match.group(2).lower()

        title_lower = (getattr(finding, "title", "") or "").lower()
        sym_lower = (getattr(finding, "symbol", "") or "").lower()

        is_mutating = (
            bool(methods & SEVERITY_FLOOR_MUTATING_METHODS)
            or any(f"mutating method {m.lower()}" in desc.lower() for m in SEVERITY_FLOOR_MUTATING_METHODS)
            or "mutating" in title_lower
            or "mutat" in desc.lower()
            or any(k in sym_lower for k in ("delete", "remove", "update", "create", "post", "put", "patch"))
            or any(f".{m.lower()}(" in evidence_content for m in SEVERITY_FLOOR_MUTATING_METHODS)
            or any(f".{m.lower()}" in evidence_content for m in SEVERITY_FLOOR_MUTATING_METHODS)
        )
        has_admin = any(term in route_path for term in SEVERITY_FLOOR_ADMIN_PATH_TERMS) or any(
            f"/{term}" in desc.lower() or f"/{term}" in evidence_content or term in desc.lower() for term in SEVERITY_FLOOR_ADMIN_PATH_TERMS
        )
        return is_mutating and has_admin

    # 3. Confirmed unauthenticated SQLi or RCE sink
    if rule_id in SEVERITY_FLOOR_INJECTION_RULES:
        desc = (getattr(finding, "description", "") or "").lower()
        title = (getattr(finding, "title", "") or "").lower()
        combined = f"{desc} {title}"
        return any(term in combined for term in ("sql", "subprocess", "command execution", "eval", "exec", "system"))

    return False


# =============================================================================
# Rule Penalty Diminishing Returns Constants
# =============================================================================
# Maximum findings evaluated at 100% full weight before logarithmic diminishing returns
RULE_FULL_WEIGHT_THRESHOLD: int = 20

# Logarithmic scaling multiplier for excess findings beyond the threshold
RULE_LOG_SCALE_FACTOR: float = 5.0

# Divisor inside the logarithm for excess findings
RULE_LOG_SCALE_DIVISOR: float = 1.0


def calculate_rule_penalty(finding_weights: list[float]) -> float:
    """Calculate rule penalty with diminishing returns so a single noisy rule cannot dominate a category.

    The first RULE_FULL_WEIGHT_THRESHOLD findings contribute at full weight.
    Subsequent findings contribute with logarithmic diminishing returns:
    excess_penalty = avg_weight * RULE_LOG_SCALE_FACTOR * ln(1 + excess / RULE_LOG_SCALE_DIVISOR).
    """
    if not finding_weights:
        return 0.0

    sorted_weights = sorted(finding_weights, reverse=True)
    n = len(sorted_weights)

    if n <= RULE_FULL_WEIGHT_THRESHOLD:
        return sum(sorted_weights)

    top_weights = sorted_weights[:RULE_FULL_WEIGHT_THRESHOLD]
    base_penalty = sum(top_weights)
    avg_top_weight = base_penalty / RULE_FULL_WEIGHT_THRESHOLD

    excess_count = n - RULE_FULL_WEIGHT_THRESHOLD
    excess_penalty = (
        avg_top_weight
        * RULE_LOG_SCALE_FACTOR
        * math.log(1.0 + excess_count / RULE_LOG_SCALE_DIVISOR)
    )

    return base_penalty + excess_penalty


