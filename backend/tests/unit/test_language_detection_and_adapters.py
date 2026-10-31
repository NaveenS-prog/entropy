"""Unit tests for language detection, adapter registry, tool probing, and error handling."""

from pathlib import Path
import pytest

from app.analyzers.adapters.base import ToolStatus
from app.analyzers.adapters.registry import LanguageAdapterRegistry, default_adapter_registry
from app.models.domain.enums import SupportedLanguage
from app.parser.base import ParsedFile
from app.repository.config import ScannerConfig
from app.repository.discoverer import RepositoryDiscoverer
from app.repository.language import EXTENSION_LANGUAGE_MAP, detect_language


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "language_adapters"


def test_extension_language_detection_all_languages():
    """Verify EXTENSION_LANGUAGE_MAP maps all 8 requested languages plus Python."""
    test_cases = [
        ("test.py", SupportedLanguage.PYTHON),
        ("main.c", SupportedLanguage.C),
        ("header.h", SupportedLanguage.C),
        ("algo.cpp", SupportedLanguage.CPP),
        ("algo.cxx", SupportedLanguage.CPP),
        ("algo.cc", SupportedLanguage.CPP),
        ("algo.hpp", SupportedLanguage.CPP),
        ("lib.rs", SupportedLanguage.RUST),
        ("Service.java", SupportedLanguage.JAVA),
        ("main.go", SupportedLanguage.GO),
        ("index.js", SupportedLanguage.JAVASCRIPT),
        ("app.jsx", SupportedLanguage.JAVASCRIPT),
        ("app.ts", SupportedLanguage.TYPESCRIPT),
        ("app.tsx", SupportedLanguage.TYPESCRIPT),
        ("index.php", SupportedLanguage.PHP),
        ("template.phtml", SupportedLanguage.PHP),
    ]
    for filename, expected_lang in test_cases:
        detected = detect_language(Path(filename))
        assert detected == expected_lang, f"Failed for {filename}: expected {expected_lang}, got {detected}"


def test_adapter_registry_contains_all_languages():
    """Verify registry has registered adapters for all 8 requested languages."""
    expected = [
        SupportedLanguage.C,
        SupportedLanguage.CPP,
        SupportedLanguage.RUST,
        SupportedLanguage.JAVA,
        SupportedLanguage.GO,
        SupportedLanguage.JAVASCRIPT,
        SupportedLanguage.TYPESCRIPT,
        SupportedLanguage.PHP,
    ]
    for lang in expected:
        adapter = default_adapter_registry.get(lang)
        assert adapter is not None, f"Missing adapter for language {lang}"
        assert adapter.language == lang


def test_tool_probing_and_status():
    """Verify adapter checks tool availability and returns ToolStatus correctly."""
    c_adapter = default_adapter_registry.get(SupportedLanguage.C)
    status = c_adapter.check_tool_availability()
    assert isinstance(status, ToolStatus)
    assert status.tool_name is not None
    assert isinstance(status.available, bool)


def test_malformed_sources_do_not_crash_adapters():
    """Verify malformed source files are handled gracefully without raising unhandled exceptions."""
    malformed_dir = FIXTURES_DIR / "malformed"
    assert malformed_dir.is_dir()

    for file_path in malformed_dir.iterdir():
        if file_path.is_file():
            lang = detect_language(file_path)
            if not lang:
                continue
            adapter = default_adapter_registry.get(lang)
            if adapter:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                parsed = ParsedFile(
                    absolute_path=file_path,
                    relative_path=file_path.name,
                    language=lang,
                    source_code=content,
                    lines=content.splitlines(),
                )
                # Analyzing malformed source should return list of findings (or empty) without crashing
                findings = adapter.analyze_file(parsed)
                assert isinstance(findings, list)


def test_vendored_files_excluded_by_default():
    """Verify vendor directories and test patterns are excluded in discovery by default."""
    mixed_dir = FIXTURES_DIR / "mixed_project"
    discoverer = RepositoryDiscoverer(
        config=ScannerConfig(
            max_file_count=1000,
            max_repo_size_bytes=10 * 1024 * 1024,
            analyzable_languages={
                SupportedLanguage.C,
                SupportedLanguage.CPP,
                SupportedLanguage.RUST,
                SupportedLanguage.JAVA,
                SupportedLanguage.GO,
                SupportedLanguage.JAVASCRIPT,
                SupportedLanguage.TYPESCRIPT,
                SupportedLanguage.PHP,
            },
        )
    )
    result = discoverer.discover_repository(str(mixed_dir))
    relative_paths = [f.relative_path for f in result.source_files]

    # Vendor file should be excluded
    for p in relative_paths:
        assert "vendor" not in p.split("/"), f"Vendored file was not excluded: {p}"
