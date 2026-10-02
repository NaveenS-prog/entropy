"""GitHub Webhook cryptographic signature verification."""

from __future__ import annotations

import hashlib
import hmac
import logging

logger = logging.getLogger("entropy.github.security")


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str | None,
    webhook_secret: str | None,
) -> bool:
    """Verify GitHub webhook payload against X-Hub-Signature-256 header using constant-time comparison.

    Non-negotiable invariants:
    - Rejects empty, missing, or malformed signature headers.
    - Rejects if no webhook secret is configured.
    - Uses constant-time HMAC-SHA256 comparison to prevent timing attacks.
    - Never logs secrets, signatures, or raw payloads.
    """
    if not webhook_secret:
        logger.warning("GitHub webhook verification failed: GITHUB_WEBHOOK_SECRET is not configured")
        return False

    if not signature_header:
        logger.warning("GitHub webhook verification failed: X-Hub-Signature-256 header is missing")
        return False

    if not signature_header.startswith("sha256="):
        logger.warning("GitHub webhook verification failed: signature header missing 'sha256=' prefix")
        return False

    expected_signature_hex = signature_header[len("sha256=") :].strip()
    if not expected_signature_hex:
        logger.warning("GitHub webhook verification failed: signature header is empty after prefix")
        return False

    # Compute expected HMAC-SHA256
    try:
        mac = hmac.new(
            key=webhook_secret.encode("utf-8"),
            msg=payload_bytes,
            digestmod=hashlib.sha256,
        )
        calculated_hex = mac.hexdigest()

        # Constant-time comparison
        is_valid = hmac.compare_digest(calculated_hex, expected_signature_hex)
        if not is_valid:
            logger.warning("GitHub webhook verification failed: HMAC signature mismatch")
        return is_valid
    except Exception as exc:
        logger.warning("GitHub webhook verification encountered unexpected error: %s", exc)
        return False
