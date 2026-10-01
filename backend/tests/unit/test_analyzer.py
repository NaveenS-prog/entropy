"""Unit tests for ErrorHandlingDebtAnalyzer."""

from pathlib import Path

from app.analyzers.base import AnalysisContext
from app.analyzers.rules.error_handling.broad_exception import ErrorHandlingDebtAnalyzer
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.parser.python_ast import PythonAstParser
from app.repository.discoverer import DiscoveredFile


def test_analyzer_detects_swallowed_and_broad_exceptions(tmp_path: Path):
    source = (
        "def process_auth():\n"
        "    try:\n"
        "        verify_signature()\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "def query_db():\n"
        "    try:\n"
        "        raw_query()\n"
        "    except:\n"
        "        log_message('failed')\n"
    )
    test_file = tmp_path / "auth.py"
    test_file.write_text(source)

    discovered = DiscoveredFile(
        absolute_path=test_file,
        relative_path="auth.py",
        language=SupportedLanguage.PYTHON,
        size_bytes=len(source),
        line_count=len(source.splitlines()),
    )

    parser = PythonAstParser()
    parsed = parser.parse(discovered)
    assert parsed.is_valid is True

    context = AnalysisContext(
        repo_path=tmp_path,
        parsed_files=[parsed],
        total_loc=discovered.line_count,
        scanned_file_count=1,
    )

    analyzer = ErrorHandlingDebtAnalyzer()
    assert analyzer.category == DebtCategory.ERROR_HANDLING
    findings = analyzer.analyze(context)

    assert len(findings) == 3

    # Finding 1: Broad exception (ENT-ERR-002)
    broad = next(f for f in findings if f.rule_id in ("ENT-ERR-002", "ERR-001"))
    assert broad.symbol == "process_auth"
    assert broad.line_start == 4
    assert broad.category == DebtCategory.ERROR_HANDLING

    # Finding 2: Empty handler (ENT-ERR-003)
    empty = next(f for f in findings if f.rule_id == "ENT-ERR-003")
    assert empty.symbol == "process_auth"
    assert empty.line_start == 4

    # Finding 3: Bare except (ENT-ERR-001)
    bare = next(f for f in findings if f.rule_id in ("ENT-ERR-001", "ERR-002"))
    assert bare.symbol == "query_db"
    assert bare.line_start == 10


def test_analyzer_clean_code_yields_zero_findings(tmp_path: Path):
    source = (
        "def clean_handling():\n"
        "    try:\n"
        "        val = int('123')\n"
        "    except ValueError as e:\n"
        "        logger.error('Invalid integer: %s', e)\n"
        "        raise\n"
    )
    test_file = tmp_path / "clean.py"
    test_file.write_text(source)

    discovered = DiscoveredFile(
        absolute_path=test_file,
        relative_path="clean.py",
        language=SupportedLanguage.PYTHON,
        size_bytes=len(source),
        line_count=len(source.splitlines()),
    )

    parser = PythonAstParser()
    parsed = parser.parse(discovered)

    context = AnalysisContext(
        repo_path=tmp_path,
        parsed_files=[parsed],
        total_loc=discovered.line_count,
        scanned_file_count=1,
    )

    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)
    assert len(findings) == 0
