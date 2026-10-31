"""Centralized weights, constants, and calibration parameters for Entropy Scoring.

All severity weights, confidence multipliers, category weights, and normalization
scaling factors are centralized in this module to avoid magic numbers.

The Entropy Score represents architectural and security debt detected by Entropy's
static-analysis rules. It does not measure vulnerability exploitability or AI authorship.
"""

from __future__ import annotations

from dataclasses import dataclass
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
# Formula: Category_Score = 100 * (1 - e^(-Weighted_Debt_Density / DENSITY_SATURATION_FACTOR))
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

# Generic prefix segments that can prefix public patterns (up to two segments)
PUBLIC_ROUTE_PREFIX_SEGMENTS: set[str] = {
    "api",
    "v1",
    "v2",
    "auth",
    "oauth",
    "oauth2",
    "accounts",
    "public",
}

# Known intentionally public route path patterns
KNOWN_PUBLIC_ROUTE_PATTERNS: list[str] = [
    "/login",
    "/login/access-token",
    "/auth/login",
    "/logout",
    "/signup",
    "/register",
    "/signin",
    "/token",
    "/oauth/token",
    "/oauth/callback",
    "/refresh",
    "/password-recovery/{email}",
    "/reset-password",
    "/forgot-password",
    "/password-reset",
    "/verify-email/{token}",
    "/health",
    "/healthz",
    "/live",
    "/ready",
    "/ping",
    "/status",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/openapi",
    "/metrics",
    "/favicon.ico",
]

# Sensitive / Administrative terms that trigger deny override:
# If ANY path segment or the handler name contains any of these terms, the route is NEVER public.
PUBLIC_DENY_TERMS: set[str] = {
    "admin",
    "internal",
    "manage",
    "management",
    "root",
    "superuser",
    "sudo",
    "impersonate",
    "any-user",
    "all-users",
    "delete",
    "export",
    "debug",
    "console",
    "payment",
    "payments",
    "refund",
}

# State-changing HTTP methods
STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "PATCH", "DELETE"}

# Explicit allowlist of terms required for state-changing public endpoints
STATE_CHANGING_PUBLIC_ALLOWLIST: set[str] = {
    "login",
    "signup",
    "register",
    "token",
    "refresh",
    "reset",
    "forgot",
    "verify",
    "logout",
    "recovery",
}

# Legacy alias for backward compatibility
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


@dataclass(frozen=True)
class PublicEndpointEvaluation:
    """Detailed result of evaluating whether an endpoint is intentionally public."""

    is_public: bool
    matched_pattern: str | None = None
    deny_term: str | None = None
    reason: str | None = None


def _is_wildcard_segment(seg: str) -> bool:
    """Check if a path segment represents a parameter wildcard."""
    if seg.startswith(":") and len(seg) > 1:
        return True
    if seg.startswith("{") and seg.endswith("}"):
        return True
    if seg.startswith("[") and seg.endswith("]"):
        return True
    return False


def _segment_matches(route_seg: str, pattern_seg: str) -> bool:
    """Compare a normalized route segment with a pattern segment."""
    if route_seg == pattern_seg:
        return True
    if _is_wildcard_segment(pattern_seg):
        # The pattern expects a wildcard param here, so any param or path token matches
        return True
    return False


def match_intentionally_public_endpoint(
    route_path: str | None,
    handler_name: str | None = None,
    http_method: str | list[str] | set[str] | None = None,
    known_patterns: list[str] | None = None,
    deny_terms: set[str] | None = None,
    prefix_segments: set[str] | None = None,
    state_changing_allowlist: set[str] | None = None,
) -> PublicEndpointEvaluation:
    """Evaluate whether a route is intentionally public using anchored matching, prefix rules, and deny override."""
    if not route_path:
        return PublicEndpointEvaluation(is_public=False, reason="Empty route path")

    patterns = known_patterns if known_patterns is not None else KNOWN_PUBLIC_ROUTE_PATTERNS
    denies = deny_terms if deny_terms is not None else PUBLIC_DENY_TERMS
    prefixes = prefix_segments if prefix_segments is not None else PUBLIC_ROUTE_PREFIX_SEGMENTS
    sc_allowlist = state_changing_allowlist if state_changing_allowlist is not None else STATE_CHANGING_PUBLIC_ALLOWLIST

    # 1. Path normalization: strip query, collapse slashes, strip whitespace, lowercase
    clean_path = route_path.split("?")[0].strip().lower()
    clean_path = re.sub(r"/+", "/", clean_path)
    segments = [s for s in clean_path.strip("/").split("/") if s]

    if not segments:
        if clean_path in ("", "/"):
            return PublicEndpointEvaluation(is_public=False, reason="Root path without public pattern")
        return PublicEndpointEvaluation(is_public=False, reason="Invalid route path")

    # 2. Deny override: if ANY path segment or handler name contains a sensitive/administrative term
    candidates = list(segments)
    if handler_name:
        candidates.append(handler_name)

    for item in candidates:
        i_lower = item.lower()
        i_hyphen = i_lower.replace("_", "-")
        i_under = i_lower.replace("-", "_")
        for deny in denies:
            d_lower = deny.lower()
            d_hyphen = d_lower.replace("_", "-")
            d_under = d_lower.replace("-", "_")
            if d_lower in i_lower or d_hyphen in i_hyphen or d_under in i_under:
                return PublicEndpointEvaluation(
                    is_public=False,
                    deny_term=deny,
                    reason=f"Deny override: sensitive term '{deny}' found in route/handler item '{item}'",
                )

    # 3. Strip up to two generic prefix segments
    candidate_segment_lists: list[list[str]] = [segments]
    if len(segments) >= 2 and segments[0] in prefixes:
        candidate_segment_lists.append(segments[1:])
    if len(segments) >= 3 and segments[0] in prefixes and segments[1] in prefixes:
        candidate_segment_lists.append(segments[2:])

    matched_pattern: str | None = None
    for cand in candidate_segment_lists:
        for pat in patterns:
            pat_clean = pat.split("?")[0].strip().lower()
            pat_clean = re.sub(r"/+", "/", pat_clean)
            pat_segments = [p for p in pat_clean.strip("/").split("/") if p]

            if len(cand) != len(pat_segments):
                continue

            if all(_segment_matches(c, p) for c, p in zip(cand, pat_segments, strict=True)):
                matched_pattern = pat
                break
        if matched_pattern:
            break

    if not matched_pattern:
        return PublicEndpointEvaluation(is_public=False, reason=f"No public pattern matched route '{clean_path}'")

    # 4. State-changing HTTP method validation
    methods: set[str] = set()
    if http_method:
        if isinstance(http_method, str):
            methods = {http_method.upper()}
        else:
            methods = {m.upper() for m in http_method if isinstance(m, str)}

    mutating_methods = methods.intersection(STATE_CHANGING_METHODS)
    if mutating_methods:
        # Must be in explicit state-changing allowlist
        pat_lower = matched_pattern.lower()
        has_allowed_sc = any(
            term in pat_lower or any(term in s for s in segments)
            for term in sc_allowlist
        )
        if not has_allowed_sc:
            return PublicEndpointEvaluation(
                is_public=False,
                matched_pattern=matched_pattern,
                reason=f"State-changing method ({', '.join(sorted(mutating_methods))}) not allowed on public endpoint '{clean_path}'",
            )

    return PublicEndpointEvaluation(
        is_public=True,
        matched_pattern=matched_pattern,
        reason=f"Matched public pattern '{matched_pattern}'",
    )


def is_intentionally_public_endpoint(
    route_path: str | None,
    handler_name: str | None = None,
    http_method: str | list[str] | set[str] | None = None,
    terms: set[str] | None = None,
) -> bool:
    """Check if a route path matches configured intentionally public patterns."""
    res = match_intentionally_public_endpoint(
        route_path=route_path,
        handler_name=handler_name,
        http_method=http_method,
    )
    return res.is_public


def handler_has_public_hint(handler_name: str | None) -> bool:
    """Check if a handler name suggests intentionally public utility (hint only, lowers confidence)."""
    if not handler_name:
        return False
    h_tokens = set(re.findall(r"[a-z0-9]+", handler_name.lower()))
    public_hint_tokens = {
        "login",
        "signin",
        "signup",
        "register",
        "logout",
        "token",
        "refresh",
        "health",
        "healthz",
        "ping",
        "status",
        "docs",
        "metrics",
    }
    return bool(h_tokens.intersection(public_hint_tokens))


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


