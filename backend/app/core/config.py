"""Entropy core configuration settings."""

from pathlib import Path

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

    model_config = SettingsConfigDict(
        env_prefix="ENTROPY_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
