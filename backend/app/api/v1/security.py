"""API security dependencies and authentication helpers for Entropy."""

from __future__ import annotations

import hmac
import logging

from fastapi import Header, HTTPException, Request, status

from app.core.config import settings

logger = logging.getLogger("entropy.security")

# Hosts permitted to access endpoints without an API key when localhost fallback is enabled
LOCALHOST_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> bool:
    """Validate API key via X-API-Key header or enforce localhost access if unconfigured."""
    configured_key = settings.API_KEY
    if configured_key:
        if not x_api_key or not hmac.compare_digest(x_api_key, configured_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Provide a valid 'X-API-Key' header.",
            )
        return True

    # No key configured: check if localhost fallback is permitted
    if not settings.ALLOW_LOCALHOST_NO_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key not configured and localhost fallback is disabled. Set ENTROPY_API_KEY.",
        )

    # Localhost fallback is allowed: enforce localhost boundary directly via peer IP (not X-Forwarded-For)
    client_host = request.client.host if request.client else None
    if client_host not in LOCALHOST_HOSTS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key not configured on server. Non-localhost access requires ENTROPY_API_KEY.",
        )
    return False


def is_authenticated_caller(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> bool:
    """Return True if the caller has presented a valid configured API key."""
    configured_key = settings.API_KEY
    if configured_key and x_api_key and hmac.compare_digest(x_api_key, configured_key):
        return True
    return False
