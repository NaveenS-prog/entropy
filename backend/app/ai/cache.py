"""Deterministic caching layer for Phase 7 AI Explanations.

Cache keys are derived from:
SHA256(finding_id + finding_fingerprint/hash + prompt_version + model)

Ensures:
- Identical finding requests are served instantly without repeated LLM calls.
- Cache is automatically invalidated if finding changes, prompt version changes, or model changes.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from app.core.config import settings
from app.models.domain.ai_explanation import AIExplanation

logger = logging.getLogger("entropy.ai.cache")


def compute_cache_key(
    finding_id: str,
    finding_hash: str,
    prompt_version: str,
    model: str,
) -> str:
    """Generate deterministic SHA256 cache key from finding identity and generation parameters."""
    composite = f"{finding_id}:{finding_hash}:{prompt_version}:{model}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()


class AIExplanationCache:
    """Persistent on-disk and in-memory cache for AI explanations."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or settings.AI_CACHE_DIR
        self._memory_cache: dict[str, AIExplanation] = {}
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Could not create AI cache directory '%s': %s", self.cache_dir, exc)

    def get(self, cache_key: str) -> AIExplanation | None:
        """Retrieve cached explanation if present and valid."""
        # 1. Check in-memory cache
        if cache_key in self._memory_cache:
            return self._memory_cache[cache_key]

        # 2. Check disk cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.is_file() and cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                explanation = AIExplanation.model_validate(data)
                self._memory_cache[cache_key] = explanation
                return explanation
            except Exception as exc:
                logger.warning("Corrupt cache file '%s' encountered: %s", cache_file, exc)
                return None

        return None

    def set(self, cache_key: str, explanation: AIExplanation) -> None:
        """Store explanation in both memory and disk cache."""
        self._memory_cache[cache_key] = explanation
        self._ensure_cache_dir()

        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            cache_file.write_text(
                explanation.model_dump_json(indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("Failed to write to AI cache file '%s': %s", cache_file, exc)

    def clear(self) -> None:
        """Clear both in-memory and disk cache entries."""
        self._memory_cache.clear()
        if self.cache_dir.exists():
            for f in self.cache_dir.glob("*.json"):
                try:
                    f.unlink()
                except Exception as exc:
                    logger.warning("Failed to remove cache file '%s': %s", f, exc)


ai_cache = AIExplanationCache()

