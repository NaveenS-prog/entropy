"""SilentGuard core configuration settings."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    APP_NAME: str = "SilentGuard"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    # CORS settings
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Analysis Defaults
    MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2MB per file limit
    SCAN_STORAGE_DIR: Path = Path("/home/naveen/silentguard/.scans")

    # Database (SQLite default for Phase 0, easily swappable for Postgres in production)
    DATABASE_URL: str = "sqlite:///./silentguard.db"

    model_config = SettingsConfigDict(
        env_prefix="SILENTGUARD_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
