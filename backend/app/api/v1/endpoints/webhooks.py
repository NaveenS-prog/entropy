"""Endpoints for receiving external webhooks (e.g. GitHub)."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request, status

from app.core.config import settings
from app.github.security import verify_webhook_signature
from app.github.service import github_workflow_service

logger = logging.getLogger("entropy.api.webhooks")
router = APIRouter()


@router.post("/github", status_code=status.HTTP_200_OK)
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(None, alias="X-GitHub-Event"),
):
    """Receive and process GitHub webhook payloads.

    Validates HMAC-SHA256 signature using GITHUB_WEBHOOK_SECRET before processing.
    """
    body_bytes = await request.body()

    # 1. Enforce Webhook Cryptographic Verification
    is_valid = verify_webhook_signature(
        payload_bytes=body_bytes,
        signature_header=x_hub_signature_256,
        webhook_secret=settings.GITHUB_WEBHOOK_SECRET,
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Hub-Signature-256 webhook signature",
        )

    # 2. Parse event payload
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        logger.warning("Failed to decode webhook JSON: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON payload",
        ) from exc

    event_name = (x_github_event or "unknown").strip().lower()

    if event_name == "ping":
        return {"status": "pong", "message": "Webhook signature verified"}

    # 3. Route to GitHub PR Workflow Service
    if event_name == "pull_request":
        try:
            record = github_workflow_service.handle_webhook_event(
                event_name=event_name,
                payload=payload,
            )
            if record is None:
                return {"status": "ignored", "event": event_name}
            return {
                "status": "processed",
                "event": event_name,
                "analysis": record,
            }
        except ValueError as val_err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(val_err),
            ) from val_err
        except Exception as exc:
            logger.exception("Error processing pull_request webhook: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"PR analysis workflow failed: {exc}",
            ) from exc

    return {"status": "ignored", "event": event_name}
