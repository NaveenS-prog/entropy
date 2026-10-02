"""Logging & Secret Handling Debt Fixture: Sensitive logs, hardcoded secrets, sensitive objects."""

import logging
import os

logger = logging.getLogger("auth_service")

# ENT-LOG-002: Hardcoded Secret / Credential Pattern (known live prefix)
STRIPE_API_KEY = "sk_live_nonproduction_test_token_12345"

# ENT-LOG-002: Hardcoded Secret with high entropy and credential name
DB_PASSWORD = "SuperSecretPassword123!"

# ENT-LOG-004: Inconsistent Secret Handling (insecure hardcoded fallback)
JWT_SECRET = os.getenv("JWT_SECRET", "insecure_fallback_jwt_secret_xyz123")

def login(request, password: str, auth_token: str):
    # ENT-LOG-001: Sensitive Data in Logs (positional argument)
    logger.info("Attempting login with password: %s", password)

    # ENT-LOG-001: Sensitive Data in Logs (f-string interpolation)
    logger.debug(f"User auth token: {auth_token}")

    # ENT-LOG-003: Sensitive Object Logging (entire request object)
    logger.info("Raw request received: %s", request)

    # ENT-LOG-003: Sensitive Object Logging (headers)
    logger.debug("Request headers: %s", request.headers)

    return {"status": "ok"}
