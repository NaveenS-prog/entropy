"""Clean Logging & Secret Handling Fixture: Safe env vars, sanitized logging."""

import logging
import os

logger = logging.getLogger("clean_service")

# Safe runtime environment secret retrieval without hardcoded default fallback
API_KEY = os.getenv("SERVICE_API_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")

def process_transaction(user_id: int, amount: float):
    # Safe logging of scalar identifiers and constant status messages
    logger.info("Starting transaction for user_id=%s, amount=%.2f", user_id, amount)
    
    if not API_KEY:
        logger.error("API_KEY environment variable is not configured")
        raise RuntimeError("Missing API_KEY")
        
    logger.info("Transaction processed successfully for user_id=%s", user_id)
    return {"status": "success", "user_id": user_id}
