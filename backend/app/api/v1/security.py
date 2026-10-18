"""API security dependencies and authentication helpers for Entropy."""

from __future__ import annotations

import logging

from fastapi import Header, HTTPException, Request, status

from app.core.config import settings

logger = logging.getLogger("entropy.security")

# Hosts permitted to access endpoints without an API key when none is configured
LOCALHOST_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> bool:
    """Validate API key via X-API-Key header or enforce localhost access if unconfigured."""
    configured_key = settings.API_KEY
    if configured_key:
        if not x_api_key or x_api_key != configured_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Provide a valid 'X-API-Key' header.",
            )
        return True

    # No key configured: enforce localhost boundary
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
    if configured_key and x_api_key and x_api_key == configured_key:
        return True
    return False
