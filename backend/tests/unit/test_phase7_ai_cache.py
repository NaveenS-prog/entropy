"""Unit tests for Phase 7 AI explanation cache."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.ai.cache import AIExplanationCache, compute_cache_key
from app.models.domain.ai_explanation import AIExplanation


def _make_explanation(finding_id: str, model: str = "test-model", prompt_version: str = "1") -> AIExplanation:
    return AIExplanation(
        finding_id=finding_id,
        summary="Test explanation summary",
        why_it_matters="Explanation of why this matters",
        evidence_explanation="Observable evidence description",
        architectural_impact="Impact assessment",
        remediation="Steps to remediate",
        suggested_pattern="suggested code pattern",
        confidence="high",
        generated_at=datetime.now(UTC),
        model=model,
        prompt_version=prompt_version,
    )


def test_same_finding_uses_cache():
    """Verify that an identical finding returns the cached explanation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cache = AIExplanationCache(cache_dir=Path(tmp_dir))
        key = compute_cache_key("f-1", "hash-abc", "1", "gemini-1.5-flash")

        explanation = _make_explanation("f-1")
        cache.set(key, explanation)

        cached = cache.get(key)
        assert cached is not None
        assert cached.finding_id == "f-1"
        assert cached.summary == explanation.summary


def test_changed_finding_invalidates_cache():
    """Verify that when a finding's content/hash changes, cache misses."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cache = AIExplanationCache(cache_dir=Path(tmp_dir))
        key_original = compute_cache_key("f-1", "hash-original", "1", "gemini-1.5-flash")
        key_modified = compute_cache_key("f-1", "hash-modified", "1", "gemini-1.5-flash")

        explanation = _make_explanation("f-1")
        cache.set(key_original, explanation)

        assert cache.get(key_original) is not None
        assert cache.get(key_modified) is None


def test_prompt_version_invalidates_cache():
    """Verify that incrementing the prompt version produces a cache miss."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cache = AIExplanationCache(cache_dir=Path(tmp_dir))
        key_v1 = compute_cache_key("f-1", "hash-abc", "1", "gemini-1.5-flash")
        key_v2 = compute_cache_key("f-1", "hash-abc", "2", "gemini-1.5-flash")

        explanation = _make_explanation("f-1", prompt_version="1")
        cache.set(key_v1, explanation)

        assert cache.get(key_v1) is not None
        assert cache.get(key_v2) is None


def test_model_change_invalidates_cache():
    """Verify that changing the AI model produces a cache miss."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cache = AIExplanationCache(cache_dir=Path(tmp_dir))
        key_model_a = compute_cache_key("f-1", "hash-abc", "1", "model-a")
        key_model_b = compute_cache_key("f-1", "hash-abc", "1", "model-b")

        explanation = _make_explanation("f-1", model="model-a")
        cache.set(key_model_a, explanation)

        assert cache.get(key_model_a) is not None
        assert cache.get(key_model_b) is None


def test_clear_cache():
    """Verify clearing the cache removes in-memory and disk entries."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cache = AIExplanationCache(cache_dir=Path(tmp_dir))
        key = compute_cache_key("f-1", "hash-abc", "1", "gemini-1.5-flash")
        cache.set(key, _make_explanation("f-1"))

        assert cache.get(key) is not None
        cache.clear()
        assert cache.get(key) is None

