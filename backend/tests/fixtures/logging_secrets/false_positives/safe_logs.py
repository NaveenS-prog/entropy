"""False Positives Mitigation Fixture: Informational log messages containing sensitive words, safe placeholders."""

import logging
import os

logger = logging.getLogger("safe_logger")

# Safe environment variables
SAFE_SECRET = os.getenv("SECRET_KEY")
SAFE_TOKEN = os.environ.get("AUTH_TOKEN")

# Placeholders that must NOT be flagged as real credentials
TEST_PLACEHOLDER_KEY = "test_placeholder"
EXAMPLE_SECRET = "changeme"
SAMPLE_DUMMY = "dummy_value"

def audit_security_events():
    # Ordinary constant strings containing sensitive words - MUST NOT be flagged as ENT-LOG-001!
    logger.info("Password must contain at least 8 characters and one symbol")
    logger.info("User requested password reset link")
    logger.info("Token validation successful for session")
    logger.info("API key format is valid")
    logger.info("Authorization header was present and verified")
    logger.warning("Session expired due to inactivity")

    return True
