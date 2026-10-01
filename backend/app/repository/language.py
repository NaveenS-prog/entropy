"""Language detection and file extension categorization."""

from pathlib import Path

from app.models.domain.enums import SupportedLanguage

EXTENSION_LANGUAGE_MAP: dict[str, SupportedLanguage] = {
    ".py": SupportedLanguage.PYTHON,
    ".pyi": SupportedLanguage.PYTHON,
    ".js": SupportedLanguage.JAVASCRIPT,
    ".jsx": SupportedLanguage.JAVASCRIPT,
    ".mjs": SupportedLanguage.JAVASCRIPT,
    ".cjs": SupportedLanguage.JAVASCRIPT,
    ".ts": SupportedLanguage.TYPESCRIPT,
    ".tsx": SupportedLanguage.TYPESCRIPT,
    ".go": SupportedLanguage.GO,
}


def detect_language(path: Path | str) -> SupportedLanguage:
    """Detect language of a file based on suffix."""
    suffix = Path(path).suffix.lower()
    return EXTENSION_LANGUAGE_MAP.get(suffix, SupportedLanguage.UNKNOWN)


def is_scannable_file(path: Path | str) -> bool:
    """Determine if a file has a supported code extension."""
    return detect_language(path) != SupportedLanguage.UNKNOWN
