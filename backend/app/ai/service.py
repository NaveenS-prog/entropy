"""AI explanation service coordinating context extraction, redaction, caching, and provider invocation."""

from __future__ import annotations

import logging
from pathlib import Path

from app.ai.cache import AIExplanationCache, ai_cache, compute_cache_key
from app.ai.context import build_explanation_context
from app.ai.provider import (
    AIProvider,
    get_ai_provider,
)
from app.core.config import settings
from app.models.domain.ai_explanation import AIExplanation
from app.models.domain.finding import Finding
from app.services.analysis_service import analysis_service
from app.services.repository_service import repository_service

logger = logging.getLogger("entropy.ai.service")


class AIDisabledError(Exception):
    """Raised when AI explanations are requested but AI_ENABLED is False."""


class FindingNotFoundError(Exception):
    """Raised when the specified finding ID does not exist."""


class AIService:
    """Service managing AI-assisted explanations for deterministic findings."""

    def __init__(
        self,
        cache: AIExplanationCache | None = None,
        provider: AIProvider | None = None,
    ) -> None:
        self.cache = cache or ai_cache
        self._provider = provider

    @property
    def provider(self) -> AIProvider:
        if self._provider is not None:
            return self._provider
        return get_ai_provider()

    def set_provider(self, provider: AIProvider | None) -> None:
        """Override the AI provider (used primarily for dependency injection in tests)."""
        self._provider = provider

    def _locate_finding(
        self, finding_id: str, scan_id: str | None = None
    ) -> tuple[str, Finding, Path | None]:
        """Locate a finding by ID, optionally scoped to a scan_id."""
        if scan_id:
            try:
                finding = analysis_service.get_finding(scan_id, finding_id)
                if finding:
                    scan = repository_service.get_scan(scan_id)
                    repo_path = Path(scan.repository.path) if scan else None
                    return scan_id, finding, repo_path
            except Exception:
                pass

        # If scan_id not provided or not found, search all scans with valid manifests
        scans = repository_service.list_scans()
        for scan in scans:
            if not scan.manifest:
                continue
            try:
                finding = analysis_service.get_finding(scan.scan_id, finding_id)
                if finding:
                    repo_path = Path(scan.repository.path)
                    return scan.scan_id, finding, repo_path
            except Exception:
                continue

        raise FindingNotFoundError(f"Finding with ID '{finding_id}' not found")

    async def explain_finding(
        self,
        finding_id: str,
        scan_id: str | None = None,
        force_refresh: bool = False,
    ) -> AIExplanation:
        """Generate or retrieve a cached AI explanation for a deterministic finding.

        Strictly advisory: never modifies the finding, severity, confidence, or entropy score.
        """
        # 1. Verify finding exists first
        _, finding, repo_path = self._locate_finding(finding_id, scan_id)

        # 2. Check AI_ENABLED
        if not settings.AI_ENABLED:
            raise AIDisabledError(
                "AI explanations are disabled. Set AI_ENABLED=true in configuration to enable."
            )

        # 3. Compute deterministic cache key
        model_name = getattr(self.provider, "model", getattr(self.provider, "model_name", settings.AI_MODEL))
        cache_key = compute_cache_key(
            finding_id=finding.id,
            finding_hash=finding.fingerprint,
            prompt_version=settings.AI_PROMPT_VERSION,
            model=model_name,
        )

        # 4. Check cache
        if not force_refresh:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.info("Serving cached AI explanation for finding '%s'", finding_id)
                return cached

        # 5. Build minimal, redacted context
        context = build_explanation_context(finding=finding, root_path=repo_path)

        # 6. Request explanation from AI provider
        logger.info(
            "Invoking AI provider '%s' (model: '%s') for finding '%s'",
            settings.AI_PROVIDER,
            model_name,
            finding_id,
        )
        explanation = await self.provider.generate_explanation(
            finding_id=finding.id,
            context=context,
        )

        # 7. Store in cache
        self.cache.set(cache_key, explanation)

        return explanation


ai_service = AIService()

