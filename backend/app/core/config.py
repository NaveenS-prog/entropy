"""Entropy core configuration settings."""

from pathlib import Path
from typing import Annotated, Any

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    APP_NAME: str = "Entropy"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    # CORS settings
    CORS_ORIGINS: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        validation_alias=AliasChoices("CORS_ORIGINS", "ENTROPY_CORS_ORIGINS"),
        description="Allowed origins for Cross-Origin Resource Sharing (CORS)",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v_str = v.strip()
            if not v_str:
                return []
            if v_str.startswith("["):
                import json
                try:
                    parsed = json.loads(v_str)
                    if isinstance(parsed, list):
                        return [str(p).strip() for p in parsed if str(p).strip()]
                except json.JSONDecodeError:
                    pass
            return [p.strip() for p in v_str.split(",") if p.strip()]
        if isinstance(v, (list, tuple)):
            return [str(p).strip() for p in v if str(p).strip()]
        return ["http://localhost:3000", "http://127.0.0.1:3000"]

    # API Security & Ingestion Boundaries
    API_KEY: str | None = Field(
        default=None,
        validation_alias=AliasChoices("API_KEY", "ENTROPY_API_KEY"),
        description="API key for securing API v1 endpoints",
    )
    ALLOW_LOCALHOST_NO_KEY: bool = Field(
        default=True,
        validation_alias=AliasChoices("ALLOW_LOCALHOST_NO_KEY", "ENTROPY_ALLOW_LOCALHOST_NO_KEY"),
        description="Allow localhost access without API key when no key is configured",
    )
    ALLOW_PUBLIC_ACCESS: bool = Field(
        default=False,
        validation_alias=AliasChoices("ALLOW_PUBLIC_ACCESS", "ENTROPY_ALLOW_PUBLIC_ACCESS"),
        description="Allow public non-localhost access without API key when no key is configured",
    )
    SCAN_ALLOWED_ROOTS: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            str(Path.cwd().resolve()),
            str(Path.cwd().parent.resolve()),
            str(Path.home().resolve()),
        ],
        validation_alias=AliasChoices("SCAN_ALLOWED_ROOTS", "ENTROPY_SCAN_ALLOWED_ROOTS"),
        description="Allowed root directory paths for repository scanning",
    )

    @field_validator("SCAN_ALLOWED_ROOTS", mode="before")
    @classmethod
    def parse_allowed_roots(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v_str = v.strip()
            if not v_str:
                return []
            if v_str.startswith("["):
                import json
                try:
                    parsed = json.loads(v_str)
                    if isinstance(parsed, list):
                        return [str(p).strip() for p in parsed if str(p).strip()]
                    raise ValueError(f"JSON array expected for allowed roots, got {type(parsed).__name__}")
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON array for allowed roots: {exc}") from exc
            return [p.strip() for p in v_str.split(",") if p.strip()]
        if isinstance(v, (list, tuple)):
            return [str(p).strip() for p in v if str(p).strip()]
        raise ValueError(f"Expected list or string for allowed roots, got {type(v).__name__}")

    # Analysis Defaults
    # Ingestion & Scanner Limits
    MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2MB per file limit
    MAX_FILES_COUNT: int = 50_000  # 50,000 files per repository
    MAX_REPO_SIZE_BYTES: int = 500 * 1024 * 1024  # 500MB total repository limit
    RESPECT_GITIGNORE: bool = True
    FOLLOW_SYMLINKS: bool = False
    SCAN_STORAGE_DIR: Path = Path(__file__).resolve().parents[3] / ".scans"

    # Database storage override
    DATABASE_URL: str | None = Field(
        default=None,
        validation_alias=AliasChoices("DATABASE_URL", "ENTROPY_DATABASE_URL"),
        description="Optional database URL for SQLite storage override (e.g. sqlite:///./entropy.db)",
    )

    # Phase 7: AI Explanation Layer Settings
    AI_ENABLED: bool = Field(
        default=True,
        validation_alias=AliasChoices("AI_ENABLED", "ENTROPY_AI_ENABLED"),
        description="Toggle AI explanation and remediation advisory layer",
    )
    AI_PROVIDER: str = Field(
        default="gemini",
        validation_alias=AliasChoices("AI_PROVIDER", "ENTROPY_AI_PROVIDER"),
        description="AI provider name: gemini, fake, openai, local",
    )
    AI_MODEL: str = Field(
        default="gemini-2.5-flash",
        validation_alias=AliasChoices("AI_MODEL", "ENTROPY_AI_MODEL"),
        description="Model name used for AI explanations",
    )
    AI_API_KEY: str | None = Field(
        default=None,
        validation_alias=AliasChoices("AI_API_KEY", "ENTROPY_AI_API_KEY", "GEMINI_API_KEY"),
        description="API key for the configured AI provider",
    )
    LOCAL_LLM_URL: str = Field(
        default="http://localhost:11434",
        validation_alias=AliasChoices("LOCAL_LLM_URL", "ENTROPY_LOCAL_LLM_URL"),
        description="Base URL for local LLM server (Ollama / OpenAI-compatible endpoint)",
    )
    LOCAL_LLM_MODEL: str = Field(
        default="k2-horizon:7b-q4",
        validation_alias=AliasChoices("LOCAL_LLM_MODEL", "ENTROPY_LOCAL_LLM_MODEL"),
        description="Model name for local LLM (k2 horizon 7b in 4Q)",
    )
    LOCAL_LLM_TIMEOUT_SECONDS: int = Field(
        default=60,
        validation_alias=AliasChoices("LOCAL_LLM_TIMEOUT_SECONDS", "ENTROPY_LOCAL_LLM_TIMEOUT_SECONDS"),
        description="HTTP timeout for local LLM provider requests",
    )
    AI_TIMEOUT_SECONDS: int = Field(
        default=60,
        validation_alias=AliasChoices("AI_TIMEOUT_SECONDS", "ENTROPY_AI_TIMEOUT_SECONDS"),
        description="HTTP timeout for AI provider requests",
    )
    AI_MAX_TOKENS: int = Field(
        default=1024,
        validation_alias=AliasChoices("AI_MAX_TOKENS", "ENTROPY_AI_MAX_TOKENS"),
        description="Maximum tokens allowed in AI response",
    )
    AI_PROMPT_VERSION: str = Field(
        default="1",
        validation_alias=AliasChoices("AI_PROMPT_VERSION", "ENTROPY_AI_PROMPT_VERSION"),
        description="Prompt version identifier for cache key derivation",
    )
    AI_CACHE_DIR: Path = Path(__file__).resolve().parents[3] / ".ai_cache"

    # Phase 12: GitHub Integration Settings
    GITHUB_ENABLED: bool = Field(
        default=False,
        validation_alias=AliasChoices("GITHUB_ENABLED", "ENTROPY_GITHUB_ENABLED"),
        description="Toggle GitHub App integration and Pull Request workflow",
    )
    GITHUB_APP_ID: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GITHUB_APP_ID", "ENTROPY_GITHUB_APP_ID"),
        description="GitHub App ID",
    )
    GITHUB_PRIVATE_KEY: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GITHUB_PRIVATE_KEY", "ENTROPY_GITHUB_PRIVATE_KEY"),
        description="GitHub App private key (PEM format)",
    )
    GITHUB_TOKEN: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GITHUB_TOKEN", "ENTROPY_GITHUB_TOKEN"),
        description="GitHub Personal Access Token or Installation Token",
    )
    GITHUB_WEBHOOK_SECRET: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GITHUB_WEBHOOK_SECRET", "ENTROPY_GITHUB_WEBHOOK_SECRET"),
        description="Secret key for validating GitHub webhook HMAC-SHA256 signatures",
    )
    GITHUB_API_BASE_URL: str = Field(
        default="https://api.github.com",
        validation_alias=AliasChoices("GITHUB_API_BASE_URL", "ENTROPY_GITHUB_API_BASE_URL"),
        description="GitHub REST API base URL",
    )
    GITHUB_TIMEOUT_SECONDS: int = Field(
        default=15,
        validation_alias=AliasChoices("GITHUB_TIMEOUT_SECONDS", "ENTROPY_GITHUB_TIMEOUT_SECONDS"),
        description="Timeout in seconds for GitHub API HTTP requests",
    )

    model_config = SettingsConfigDict(
        env_prefix="ENTROPY_",
        env_file=(".env", str(Path(__file__).resolve().parent.parent.parent / ".env")),
        extra="ignore",
    )


settings = Settings()
