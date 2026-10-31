"""Integration tests for multi-language repository scanning, CLI commands, and filtering."""

import json
from pathlib import Path
import pytest

from app.cli.main import (
    EXIT_CONFIG_ERROR,
    EXIT_PASS,
    _run_single_scan_pipeline,
    main,
)
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.scan import ScanStatus


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "language_adapters"
MIXED_PROJECT_DIR = FIXTURES_DIR / "mixed_project"


def test_mixed_language_scan_pipeline_end_to_end():
    """Verify scanning a mixed-language repository discovers all languages, detects findings,

    and computes a valid deterministic debt score.
    """
    scan, findings = _run_single_scan_pipeline(
        repo_path=MIXED_PROJECT_DIR,
        include_tests=False,
    )

    assert scan.status == ScanStatus.COMPLETED
    assert scan.score is not None
    assert 0 <= scan.score.total_score <= 100

    # Ensure findings exist across multiple languages
    detected_languages = {f.language for f in findings if f.language}
    assert SupportedLanguage.C in detected_languages
    assert SupportedLanguage.GO in detected_languages
    assert SupportedLanguage.RUST in detected_languages
    assert SupportedLanguage.PHP in detected_languages
    assert SupportedLanguage.TYPESCRIPT in detected_languages

    # Check vendor exclusion: no finding from vendor/ignored.c
    for f in findings:
        assert "vendor" not in f.file.split("/"), f"Finding detected in vendored directory: {f.file}"


def test_cli_languages_filter_selection(capsys):
    """Verify CLI --languages / -l option limits analysis to specified languages."""
    exit_code = main(["scan", str(MIXED_PROJECT_DIR), "--languages", "rust,go", "--format", "json"])
    assert exit_code == EXIT_PASS

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    findings = data["top_findings"]

    # All top findings must be only from Rust or Go
    for f in findings:
        assert f["language"] in ("rust", "go"), f"Expected only rust/go findings, found: {f['language']}"


def test_cli_languages_filter_invalid_language(capsys):
    """Verify CLI reports configuration error when an unsupported language is provided."""
    exit_code = main(["scan", str(MIXED_PROJECT_DIR), "--languages", "brainfuck,rust"])
    assert exit_code == EXIT_CONFIG_ERROR

    captured = capsys.readouterr()
    assert "Unknown language 'brainfuck'" in captured.err


def test_cli_findings_text_output_includes_language_and_remedy(capsys):
    """Verify CLI findings text output displays Language, Confidence, Remedy, and Ref."""
    exit_code = main(["findings", str(MIXED_PROJECT_DIR), "--languages", "php"])
    assert exit_code == EXIT_PASS

    captured = capsys.readouterr()
    out = captured.out
    assert "Language: php" in out
    assert "Confidence: high" in out
    assert "Remedy:" in out
    assert "Ref:" in out


def test_cli_scan_sarif_format_multilang(capsys):
    """Verify CLI generates valid SARIF format containing multi-language findings."""
    exit_code = main(["scan", str(MIXED_PROJECT_DIR), "--format", "sarif"])
    assert exit_code == EXIT_PASS

    captured = capsys.readouterr()
    sarif = json.loads(captured.out)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) > 0
    results = sarif["runs"][0]["results"]
    assert len(results) > 0
