"""Secret redaction utility for Phase 7 AI Explanation & Remediation Layer.

Ensures sensitive values, API keys, credentials, and private keys are redacted
before being transmitted to an external LLM provider.
"""

from __future__ import annotations

import re

REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_KEY = "[REDACTED_PRIVATE_KEY]"

# Regex patterns for high-confidence tokens and prefixes
TOKEN_PATTERNS = [
    # Stripe live & test keys
    (re.compile(r"\b(sk_live_[0-9a-zA-Z_]+)\b"), REDACTED_SECRET),
    (re.compile(r"\b(sk_test_[0-9a-zA-Z_]+)\b"), REDACTED_SECRET),
    (re.compile(r"\b(rk_live_[0-9a-zA-Z_]+)\b"), REDACTED_SECRET),
    # GitHub tokens
    (re.compile(r"\b(ghp_[0-9a-zA-Z_]{20,})\b"), REDACTED_SECRET),
    (re.compile(r"\b(gho_[0-9a-zA-Z_]{20,})\b"), REDACTED_SECRET),
    (re.compile(r"\b(ghu_[0-9a-zA-Z_]{20,})\b"), REDACTED_SECRET),
    (re.compile(r"\b(ghs_[0-9a-zA-Z_]{20,})\b"), REDACTED_SECRET),
    (re.compile(r"\b(ghr_[0-9a-zA-Z_]{20,})\b"), REDACTED_SECRET),
    # GitLab personal tokens
    (re.compile(r"\b(glpat-[0-9a-zA-Z_-]{20,})\b"), REDACTED_SECRET),
    # Slack tokens
    (re.compile(r"\b(xoxb-[0-9a-zA-Z_-]+)\b"), REDACTED_SECRET),
    (re.compile(r"\b(xoxp-[0-9a-zA-Z_-]+)\b"), REDACTED_SECRET),
    (re.compile(r"\b(xoxa-[0-9a-zA-Z_-]+)\b"), REDACTED_SECRET),
    (re.compile(r"\b(xoxr-[0-9a-zA-Z_-]+)\b"), REDACTED_SECRET),
    # AWS access key ID
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), REDACTED_SECRET),
    # Google API Key
    (re.compile(r"\b(AIzaSy[0-9A-Za-z_-]{25,})\b"), REDACTED_SECRET),
    # Generic bearer tokens
    (
        re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]{20,}=*", re.IGNORECASE),
        rf"\g<1>{REDACTED_SECRET}",
    ),
]

# Multiline private key block pattern
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]+PRIVATE KEY-----"
)

# Sensitive assignment pattern (e.g. API_KEY = "...", password="...", gemini_key="...")
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)\b([a-zA-Z0-9_]*(?:api_key|apikey|secret|password|passwd|token|access_token|refresh_token|auth_token|client_secret|private_key|_key)\b)(\s*[:=]\s*)(["'])(.+?)\3"""
)


def redact_secrets(text: str | None) -> str:
    """Scan and redact all sensitive keys, tokens, and assignments in the text."""
    if not text:
        return ""

    redacted = text

    # 1. Redact private key blocks
    redacted = PRIVATE_KEY_PATTERN.sub(REDACTED_KEY, redacted)

    # 2. Redact sensitive variable / dict assignments
    def _replace_assignment(match: re.Match) -> str:
        var_name = match.group(1)
        sep_with_space = match.group(2)
        quote = match.group(3)
        val = match.group(4)
        # Avoid double-redacting
        if val == REDACTED_SECRET or val == REDACTED_KEY:
            return match.group(0)
        return f"{var_name}{sep_with_space}{quote}{REDACTED_SECRET}{quote}"

    redacted = SENSITIVE_ASSIGNMENT_PATTERN.sub(_replace_assignment, redacted)

    # 3. Redact specific high-confidence token prefixes
    for pattern, replacement in TOKEN_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    return redacted

