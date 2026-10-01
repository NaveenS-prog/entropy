"""Language detection and file extension categorization."""

from pathlib import Path

from app.models.domain.enums import SupportedLanguage

# Map of file extensions to recognized programming languages
EXTENSION_LANGUAGE_MAP: dict[str, SupportedLanguage] = {
    # Python
    ".py": SupportedLanguage.PYTHON,
    ".pyi": SupportedLanguage.PYTHON,
    # JavaScript
    ".js": SupportedLanguage.JAVASCRIPT,
    ".jsx": SupportedLanguage.JAVASCRIPT,
    ".mjs": SupportedLanguage.JAVASCRIPT,
    ".cjs": SupportedLanguage.JAVASCRIPT,
    # TypeScript
    ".ts": SupportedLanguage.TYPESCRIPT,
    ".tsx": SupportedLanguage.TYPESCRIPT,
    ".mts": SupportedLanguage.TYPESCRIPT,
    ".cts": SupportedLanguage.TYPESCRIPT,
    # Classification only languages
    ".java": SupportedLanguage.JAVA,
    ".c": SupportedLanguage.C,
    ".h": SupportedLanguage.C,
    ".cpp": SupportedLanguage.CPP,
    ".hpp": SupportedLanguage.CPP,
    ".cc": SupportedLanguage.CPP,
    ".cxx": SupportedLanguage.CPP,
    ".go": SupportedLanguage.GO,
    ".rs": SupportedLanguage.RUST,
}

# Currently, only Python has active AST parsers and analyzers implemented in Entropy
ANALYZABLE_LANGUAGES: set[SupportedLanguage] = {
    SupportedLanguage.PYTHON,
}

UNAVAILABLE_ANALYZER_REASON = "language_detected_but_analyzer_unavailable"


def detect_language(path: Path | str) -> SupportedLanguage:
    """Detect language of a file based on file suffix."""
    suffix = Path(path).suffix.lower()
    return EXTENSION_LANGUAGE_MAP.get(suffix, SupportedLanguage.UNKNOWN)


def is_scannable_file(path: Path | str) -> bool:
    """Determine if a file has a recognized programming language extension."""
    return detect_language(path) != SupportedLanguage.UNKNOWN


def is_analysis_supported(language: SupportedLanguage) -> bool:
    """Check if full static analysis is supported for the given language in this phase."""
    return language in ANALYZABLE_LANGUAGES


def get_analysis_skip_reason(language: SupportedLanguage) -> str | None:
    """Return explicit honest reason why analysis is not supported for this language."""
    if language == SupportedLanguage.UNKNOWN:
        return "unrecognized_language"
    if not is_analysis_supported(language):
        return UNAVAILABLE_ANALYZER_REASON
    return None
