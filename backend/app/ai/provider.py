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


class LocalLLMProvider:
    """Local LLM provider supporting Ollama and local OpenAI-compatible endpoints.

    Designed for local model execution in the terminal (default: k2 horizon 7b in 4Q,
    configured as 'k2-horizon:7b-q4').
    """

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self.base_url = (base_url or getattr(settings, "LOCAL_LLM_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or getattr(settings, "LOCAL_LLM_MODEL", "k2-horizon:7b-q4")
        self.timeout = timeout or getattr(settings, "LOCAL_LLM_TIMEOUT_SECONDS", 60)
        self.max_tokens = max_tokens or settings.AI_MAX_TOKENS
        self.prompt_version = settings.AI_PROMPT_VERSION

    def _extract_json_payload(self, text: str) -> dict[str, Any]:
        """Safely extract JSON object from LLM response text."""
        cleaned = text.strip()
        # Handle markdown ```json ... ``` fences
        if "```json" in cleaned:
            parts = cleaned.split("```json")
            if len(parts) > 1:
                content = parts[1].split("```")[0].strip()
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    pass
        elif "```" in cleaned:
            parts = cleaned.split("```")
            if len(parts) > 1:
                content = parts[1].strip()
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    pass

        # Try finding outer braces { ... }
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(cleaned[start : end + 1])
            except json.JSONDecodeError:
                pass

        # Fallback to direct json.loads
        return json.loads(cleaned)

    async def generate_explanation(
        self,
        finding_id: str,
        context: AIExplanationContext,
    ) -> AIExplanation:
        """Generate structured advisory explanation using a local LLM."""
        user_prompt = build_user_prompt(context)

        # 1. First attempt Ollama chat endpoint: /api/chat with format=json
        ollama_url = f"{self.base_url}/api/chat"
        ollama_payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT_V1},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "num_predict": self.max_tokens,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
                resp = None
                is_ollama = True
                try:
                    resp = await client.post(ollama_url, json=ollama_payload)
                    if resp.status_code == 404:
                        is_ollama = False
                except (httpx.ConnectError, httpx.NetworkError):
                    raise AIProviderUnavailableError(
                        f"Local LLM service is not reachable at {self.base_url}.\n"
                        f"Please ensure Ollama or your local LLM runtime is running.\n"
                        f"For model '{self.model}', run: 'ollama run {self.model}' or 'ollama serve'."
                    )

                raw_text = ""
                if is_ollama and resp is not None:
                    if resp.status_code == 404:
                        is_ollama = False
                    elif resp.status_code >= 400:
                        err_text = resp.text
                        if "not found" in err_text.lower():
                            raise AIProviderUnavailableError(
                                f"Model '{self.model}' not found in local Ollama instance.\n"
                                f"Please run: 'ollama pull {self.model}' or specify an available model with --model."
                            )
                        raise AIProviderError(f"Local LLM returned HTTP {resp.status_code}: {err_text}")
                    else:
                        data = resp.json()
                        raw_text = data.get("message", {}).get("content", "")

                # If /api/chat is not supported, attempt OpenAI-compatible endpoint /v1/chat/completions
                if not is_ollama:
                    openai_url = f"{self.base_url}/v1/chat/completions"
                    openai_payload: dict[str, Any] = {
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT_V1},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.2,
                        "max_tokens": self.max_tokens,
                    }
                    resp = await client.post(openai_url, json=openai_payload)
                    if resp.status_code >= 400:
                        raise AIProviderError(f"Local LLM returned HTTP {resp.status_code}: {resp.text}")
                    data = resp.json()
                    choices = data.get("choices", [])
                    if not choices:
                        raise AIProviderMalformedResponseError("No choices returned from local LLM response")
                    raw_text = choices[0].get("message", {}).get("content", "")

                if not raw_text.strip():
                    raise AIProviderMalformedResponseError("Local LLM returned empty response")

                parsed_json = self._extract_json_payload(raw_text)

                return AIExplanation(
                    finding_id=finding_id,
                    summary=parsed_json.get("summary") or f"Analysis of {context.rule_id} in {context.file_path}",
                    why_it_matters=parsed_json.get("why_it_matters")
                    or f"Pattern under category '{context.category}' introduces architectural debt.",
                    evidence_explanation=parsed_json.get("evidence_explanation")
                    or f"Observable evidence at lines {context.line_start}-{context.line_end}: {context.message}",
                    architectural_impact=parsed_json.get("architectural_impact")
                    or "Unaddressed debt increases maintenance hazards and structural drift.",
                    remediation=parsed_json.get("remediation")
                    or f"Refactor {context.file_path} to comply with standard security and architectural guidelines.",
                    suggested_pattern=parsed_json.get("suggested_pattern") or "",
                    confidence=str(parsed_json.get("confidence", "medium")),
                    generated_at=datetime.now(UTC),
                    model=self.model,
                    prompt_version=self.prompt_version,
                )

        except httpx.TimeoutException as exc:
            msg = f"Local LLM request timed out after {self.timeout}s: {exc}"
            logger.warning("%s", msg)
            raise AIProviderTimeoutError(f"Local LLM inference timed out after {self.timeout}s") from None
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            msg = f"Network error connecting to Local LLM at {self.base_url}: {exc}"
            logger.warning("%s", msg)
            raise AIProviderUnavailableError(
                f"Local LLM is not reachable at {self.base_url}.\n"
                f"Please ensure Ollama or local LLM server is running. Command: 'ollama run {self.model}'."
            ) from None
        except json.JSONDecodeError as exc:
            msg = f"Failed to decode JSON from Local LLM response: {exc}"
            logger.warning("%s", msg)
            raise AIProviderMalformedResponseError(msg) from None
        except ValidationError as exc:
            msg = f"Validation failed for Local LLM AIExplanation: {exc}"
            logger.warning("%s", msg)
            raise AIProviderMalformedResponseError(msg) from None
        except AIProviderError:
            raise
        except Exception as exc:
            msg = f"Unexpected error communicating with Local LLM: {exc}"
            logger.warning("%s", msg)
            raise AIProviderError(msg) from None


def get_ai_provider(provider_name: str | None = None, **kwargs: Any) -> AIProvider:
    """Return an instance of the configured AI provider."""
    name = (provider_name or settings.AI_PROVIDER).lower().strip()
    if name == "fake":
        kwargs.setdefault("model_name", "fake-provider")
        return FakeAIProvider(**kwargs)
    elif name == "gemini":
        return GeminiProvider(**kwargs)
    elif name in ("local", "localllm", "ollama", "k2", "k2-horizon", "k2 horizon"):
        return LocalLLMProvider(**kwargs)
    elif name == "openai":
        raise AIProviderConfigError("OpenAI provider is not yet enabled. Use 'gemini', 'local', or 'fake'.")
    else:
        logger.warning("Unknown AI provider '%s', falling back to FakeAIProvider", name)
        return FakeAIProvider()
