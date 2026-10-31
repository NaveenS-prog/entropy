"""AI provider interface and implementations for Phase 7 AI Explanation Layer.

Includes:
- AIProvider Protocol
- Custom AI exception hierarchy
- FakeAIProvider for testing and offline execution
- GeminiProvider for live API execution
- Provider factory
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx
from pydantic import ValidationError

from app.ai.prompts import SYSTEM_PROMPT_V1, build_user_prompt
from app.core.config import settings
from app.models.domain.ai_explanation import AIExplanation, AIExplanationContext

logger = logging.getLogger("entropy.ai.provider")


class AIProviderError(Exception):
    """Base exception for AI provider operations."""


class AIProviderConfigError(AIProviderError):
    """Raised when provider configuration is missing or invalid."""


class AIProviderTimeoutError(AIProviderError):
    """Raised when an AI provider request times out."""


class AIProviderUnavailableError(AIProviderError):
    """Raised when the AI provider service is down or unreachable."""


class AIProviderMalformedResponseError(AIProviderError):
    """Raised when the AI provider returns an invalid or unparseable response."""


class AIProvider(Protocol):
    """Abstract protocol for AI explanation providers."""

    async def generate_explanation(
        self,
        finding_id: str,
        context: AIExplanationContext,
    ) -> AIExplanation:
        """Generate structured advisory explanation for a finding."""
        ...


class FakeAIProvider:
    """Deterministic, local test provider that produces grounded explanations without network requests."""

    def __init__(
        self,
        simulate_timeout: bool = False,
        simulate_error: bool = False,
        simulate_malformed: bool = False,
        model_name: str = "fake-entropy-explainer",
        prompt_version: str | None = None,
    ) -> None:
        self.simulate_timeout = simulate_timeout
        self.simulate_error = simulate_error
        self.simulate_malformed = simulate_malformed
        self.model_name = model_name
        self.prompt_version = prompt_version or settings.AI_PROMPT_VERSION
        self.call_count = 0

    async def generate_explanation(
        self,
        finding_id: str,
        context: AIExplanationContext,
    ) -> AIExplanation:
        self.call_count += 1

        if self.simulate_timeout:
            raise AIProviderTimeoutError("AI request timed out during inference")

        if self.simulate_error:
            raise AIProviderUnavailableError("Simulated AI provider failure")

        if self.simulate_malformed:
            raise AIProviderMalformedResponseError("Simulated malformed response from LLM")

        # Produce realistic, grounded explanation strictly reflecting deterministic context
        return AIExplanation(
            finding_id=finding_id,
            summary=f"Analysis of {context.rule_id} ({context.severity} severity) in {context.file_path}",
            why_it_matters=(
                f"The pattern detected under category '{context.category}' creates maintenance "
                f"and security hazards by deviating from standardized conventions."
            ),
            evidence_explanation=(
                f"Observable evidence located at lines {context.line_start}-{context.line_end} "
                f"shows: {context.message}"
            ),
            architectural_impact=(
                "Unaddressed architectural debt increases cognitive load during code reviews "
                "and can lead to cascading failures under unexpected operational conditions."
            ),
            remediation=(
                f"Refactor the code block in {context.file_path} to explicitly adhere to the "
                f"framework or language standard corresponding to {context.rule_id}."
            ),
            suggested_pattern=(
                "# Standardized architectural pattern\n"
                f"# Address {context.rule_id} by enforcing explicit handling and contracts"
            ),
            confidence="medium",
            generated_at=datetime.now(UTC),
            model=self.model_name,
            prompt_version=self.prompt_version,
        )


class GeminiProvider:
    """Google Gemini AI provider via REST API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self.api_key = api_key or settings.AI_API_KEY
        self.model = model or settings.AI_MODEL
        self.timeout = timeout or settings.AI_TIMEOUT_SECONDS
        self.max_tokens = max_tokens or settings.AI_MAX_TOKENS
        self.prompt_version = settings.AI_PROMPT_VERSION

    def _sanitize(self, text: str) -> str:
        """Strip API key from log or error message string."""
        if self.api_key and self.api_key in text:
            return text.replace(self.api_key, "[REDACTED]")
        return text

    async def generate_explanation(
        self,
        finding_id: str,
        context: AIExplanationContext,
    ) -> AIExplanation:
        if not self.api_key:
            raise AIProviderConfigError(
                "Gemini API key is not configured. Set ENTROPY_AI_API_KEY or AI_API_KEY."
            )

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        user_prompt = build_user_prompt(context)

        payload: dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "systemInstruction": {
                "role": "system",
                "parts": [{"text": SYSTEM_PROMPT_V1}],
            },
            "generationConfig": {
                "responseMimeType": "application/json",
                "maxOutputTokens": self.max_tokens,
                "temperature": 0.2,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
                response = await client.post(url, headers=headers, json=payload)

            if response.status_code == 429:
                raise AIProviderUnavailableError("Gemini rate limit exceeded. Please retry later.")
            elif response.status_code >= 500:
                raise AIProviderUnavailableError(
                    f"Gemini service unavailable (HTTP {response.status_code})"
                )
            elif response.status_code >= 400:
                error_body = self._sanitize(response.text)
                raise AIProviderError(
                    f"Gemini API returned error status {response.status_code}: {error_body}"
                )

            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise AIProviderMalformedResponseError("No candidates returned in Gemini response")

            content_parts = candidates[0].get("content", {}).get("parts", [])
            if not content_parts or "text" not in content_parts[0]:
                raise AIProviderMalformedResponseError("Candidate missing text content")

            raw_text = content_parts[0]["text"]
            parsed_json = json.loads(raw_text)

            return AIExplanation(
                finding_id=finding_id,
                summary=parsed_json.get("summary", ""),
                why_it_matters=parsed_json.get("why_it_matters", ""),
                evidence_explanation=parsed_json.get("evidence_explanation", ""),
                architectural_impact=parsed_json.get("architectural_impact", ""),
                remediation=parsed_json.get("remediation", ""),
                suggested_pattern=parsed_json.get("suggested_pattern", ""),
                confidence=str(parsed_json.get("confidence", "medium")),
                generated_at=datetime.now(UTC),
                model=self.model,
                prompt_version=self.prompt_version,
            )

        except httpx.TimeoutException as exc:
            msg = self._sanitize(f"Gemini API call timed out after {self.timeout}s: {exc}")
            logger.warning("%s", msg)
            raise AIProviderTimeoutError(f"AI provider request timed out after {self.timeout}s") from None
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            msg = self._sanitize(f"Network error connecting to AI provider: {exc}")
            logger.warning("%s", msg)
            raise AIProviderUnavailableError(msg) from None
        except json.JSONDecodeError as exc:
            msg = self._sanitize(f"Failed to decode JSON from Gemini output: {exc}")
            logger.warning("%s", msg)
            raise AIProviderMalformedResponseError(msg) from None
        except ValidationError as exc:
            msg = self._sanitize(f"Validation failed for AIExplanation: {exc}")
            logger.warning("%s", msg)
            raise AIProviderMalformedResponseError(msg) from None
        except AIProviderError:
            raise
        except Exception as exc:
            msg = self._sanitize(f"Unexpected error communicating with AI provider: {exc}")
            logger.warning("%s", msg)
            raise AIProviderError(msg) from None


class OpenAIProvider:
    """OpenAI and OpenAI-compatible AI provider via REST API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self.api_key = api_key or settings.AI_API_KEY
        self.model = model or (
            settings.AI_MODEL
            if settings.AI_MODEL and "gemini" not in settings.AI_MODEL
            else "gpt-4o-mini"
        )
        base = base_url or settings.AI_BASE_URL or "https://api.openai.com/v1"
        self.base_url = base.rstrip("/")
        self.timeout = timeout or settings.AI_TIMEOUT_SECONDS
        self.max_tokens = max_tokens or settings.AI_MAX_TOKENS
        self.prompt_version = settings.AI_PROMPT_VERSION

    def _sanitize(self, text: str) -> str:
        """Strip API key from log or error message string."""
        if self.api_key and self.api_key in text:
            return text.replace(self.api_key, "[REDACTED]")
        return text

    async def generate_explanation(
        self,
        finding_id: str,
        context: AIExplanationContext,
    ) -> AIExplanation:
        if not self.api_key:
            raise AIProviderConfigError(
                "OpenAI API key is not configured. Set ENTROPY_AI_API_KEY, AI_API_KEY, or OPENAI_API_KEY."
            )

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        user_prompt = build_user_prompt(context)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT_V1},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
                response = await client.post(url, headers=headers, json=payload)

            if response.status_code == 429:
                raise AIProviderUnavailableError("OpenAI rate limit exceeded. Please retry later.")
            elif response.status_code >= 500:
                raise AIProviderUnavailableError(
                    f"OpenAI service unavailable (HTTP {response.status_code})"
                )
            elif response.status_code >= 400:
                error_body = self._sanitize(response.text)
                raise AIProviderError(
                    f"OpenAI API returned error status {response.status_code}: {error_body}"
                )

            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                raise AIProviderMalformedResponseError("No choices returned in OpenAI response")

            message = choices[0].get("message", {})
            raw_text = message.get("content", "")
            if not raw_text:
                raise AIProviderMalformedResponseError("Choice missing content in OpenAI response")

            parsed_json = json.loads(raw_text)

            return AIExplanation(
                finding_id=finding_id,
                summary=parsed_json.get("summary", ""),
                why_it_matters=parsed_json.get("why_it_matters", ""),
                evidence_explanation=parsed_json.get("evidence_explanation", ""),
                architectural_impact=parsed_json.get("architectural_impact", ""),
                remediation=parsed_json.get("remediation", ""),
                suggested_pattern=parsed_json.get("suggested_pattern", ""),
                confidence=str(parsed_json.get("confidence", "medium")),
                generated_at=datetime.now(UTC),
                model=self.model,
                prompt_version=self.prompt_version,
            )

        except httpx.TimeoutException as exc:
            msg = self._sanitize(f"OpenAI API call timed out after {self.timeout}s: {exc}")
            logger.warning("%s", msg)
            raise AIProviderTimeoutError(f"AI provider request timed out after {self.timeout}s") from None
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            msg = self._sanitize(f"Network error connecting to OpenAI provider: {exc}")
            logger.warning("%s", msg)
            raise AIProviderUnavailableError(msg) from None
        except json.JSONDecodeError as exc:
            msg = self._sanitize(f"Failed to decode JSON from OpenAI output: {exc}")
            logger.warning("%s", msg)
            raise AIProviderMalformedResponseError(msg) from None
        except ValidationError as exc:
            msg = self._sanitize(f"Validation failed for AIExplanation: {exc}")
            logger.warning("%s", msg)
            raise AIProviderMalformedResponseError(msg) from None
        except AIProviderError:
            raise
        except Exception as exc:
            msg = self._sanitize(f"Unexpected error communicating with OpenAI provider: {exc}")
            logger.warning("%s", msg)
            raise AIProviderError(msg) from None


def get_ai_provider() -> AIProvider:
    """Return an instance of the configured AI provider."""
    provider_name = settings.AI_PROVIDER.lower().strip()
    if provider_name == "fake":
        return FakeAIProvider(model_name="fake-provider")
    elif provider_name == "gemini":
        return GeminiProvider()
    elif provider_name == "openai":
        return OpenAIProvider()
    else:
        logger.warning("Unknown AI provider '%s', falling back to FakeAIProvider", provider_name)
        return FakeAIProvider()
