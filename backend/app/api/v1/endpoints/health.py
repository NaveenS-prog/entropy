"""Health check and system telemetry endpoint."""

from fastapi import APIRouter

from app.analyzers.registry import default_registry
from app.core.config import settings
from app.models.domain.enums import SupportedLanguage

router = APIRouter()


@router.get("/health", summary="System Health & Telemetry")
def get_health() -> dict:
    """Return system readiness, active analyzers, and supported language parsers."""
    analyzers = default_registry.get_all()
    rules = default_registry.list_rules()

    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "active_analyzers_count": len(analyzers),
        "total_rules_count": len(rules),
        "supported_languages": [
            SupportedLanguage.PYTHON.value,
            SupportedLanguage.TYPESCRIPT.value,
            SupportedLanguage.JAVASCRIPT.value,
            SupportedLanguage.GO.value,
        ],
    }
