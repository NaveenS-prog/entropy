"""Entropy core configuration settings."""

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    APP_NAME: str = "Entropy"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    # CORS settings
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Analysis Defaults
    # Ingestion & Scanner Limits
    MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2MB per file limit
    MAX_FILES_COUNT: int = 50_000  # 50,000 files per repository
    MAX_REPO_SIZE_BYTES: int = 500 * 1024 * 1024  # 500MB total repository limit
    RESPECT_GITIGNORE: bool = True
    FOLLOW_SYMLINKS: bool = False
    SCAN_STORAGE_DIR: Path = Path(__file__).resolve().parents[3] / ".scans"

    # Database (SQLite default for Phase 0, easily swappable for Postgres in production)
    DATABASE_URL: str = "sqlite:///./entropy.db"

    # Phase 7: AI Explanation Layer Settings
    AI_ENABLED: bool = Field(
        default=False,
        validation_alias=AliasChoices("AI_ENABLED", "ENTROPY_AI_ENABLED"),
        description="Toggle AI explanation and remediation advisory layer",
    )
    AI_PROVIDER: str = Field(
        default="gemini",
        validation_alias=AliasChoices("AI_PROVIDER", "ENTROPY_AI_PROVIDER"),
        description="AI provider name: gemini, fake, openai",
    )
    AI_MODEL: str = Field(
        default="gemini-1.5-flash",
        validation_alias=AliasChoices("AI_MODEL", "ENTROPY_AI_MODEL"),
        description="Model name used for AI explanations",
    )
    AI_API_KEY: str | None = Field(
        default=None,
        validation_alias=AliasChoices("AI_API_KEY", "ENTROPY_AI_API_KEY", "GEMINI_API_KEY"),
        description="API key for the configured AI provider",
    )
    AI_TIMEOUT_SECONDS: int = Field(
        default=30,
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

    model_config = SettingsConfigDict(
        env_prefix="ENTROPY_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
