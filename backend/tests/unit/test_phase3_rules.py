"""Comprehensive Phase 3 Unit Tests for Error Handling Debt Rules & Findings Engine.

Tests cover:
- ENT-ERR-001: Bare except clause
- ENT-ERR-002: Broad exception handler (Exception, BaseException, tuple including Exception)
- ENT-ERR-003: Empty exception handler (pass, ellipsis, docstring-only)
- ENT-ERR-004: Silently swallowed exception (and suppression when ENT-ERR-003 fired)
- ENT-ERR-005: Generic fallback return (None, False, True, {}, [], "")
- ENT-ERR-006: Explicitly DEFERRED status verification
- Deterministic Finding ID generation (SHA256 formula)
- Deterministic finding sorting (file, line_start, rule_id)
- Zero false positives on clean idiom patterns (proper logging, explicit raise)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analyzers.base import AnalysisContext
from app.analyzers.rules.error_handling.analyzer import ErrorHandlingDebtAnalyzer
from app.analyzers.rules.error_handling.rules import (
    RULE_ERR_006_DEFERRED,
)
from app.models.domain.enums import DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.parser.python_ast import PythonAstParser
from app.repository.discoverer import DiscoveredFile


def _parse_and_create_context(tmp_path: Path, filename: str, source: str) -> AnalysisContext:
    test_file = tmp_path / filename
    test_file.write_text(source, encoding="utf-8")

    discovered = DiscoveredFile(
        absolute_path=test_file,
        relative_path=filename,
        language=SupportedLanguage.PYTHON,
        size_bytes=len(source.encode("utf-8")),
        line_count=len(source.splitlines()),
    )
    parser = PythonAstParser()
    parsed = parser.parse(discovered)
    assert parsed.is_valid, f"Source parse failed: {parsed.errors}"

    return AnalysisContext(
        repo_path=tmp_path,
        parsed_files=[parsed],
        total_loc=discovered.line_count,
        scanned_file_count=1,
    )


# ==============================================================================
# ENT-ERR-001: Bare Except Rule Tests
# ==============================================================================


def test_ent_err_001_bare_except_detected(tmp_path: Path):
    source = (
        "def run_job():\n"
        "    try:\n"
        "        do_work()\n"
        "    except:\n"
        "        log_error('failed')\n"
    )
    context = _parse_and_create_context(tmp_path, "job.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    bare_findings = [f for f in findings if f.rule_id == "ENT-ERR-001"]
    assert len(bare_findings) == 1
    f = bare_findings[0]
    assert f.rule_id == "ENT-ERR-001"
    assert f.line_start == 4
    assert f.symbol == "run_job"
    assert f.category == DebtCategory.ERROR_HANDLING
    assert "bare 'except:'" in f.description
    assert f.evidence.line_start <= 4 <= f.evidence.line_end


def test_ent_err_001_specific_except_not_flagged(tmp_path: Path):
    source = (
        "def safe_parse():\n"
        "    try:\n"
        "        int('abc')\n"
        "    except ValueError:\n"
        "        log.warning('Parsing error')\n"
    )
    context = _parse_and_create_context(tmp_path, "parse.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    bare_findings = [f for f in findings if f.rule_id == "ENT-ERR-001"]
    assert len(bare_findings) == 0


# ==============================================================================
# ENT-ERR-002: Broad Exception Handler Rule Tests
# ==============================================================================


@pytest.mark.parametrize(
    "clause",
    [
        "except Exception:",
        "except BaseException:",
        "except (KeyError, Exception):",
        "except (BaseException, ValueError):",
    ],
)
def test_ent_err_002_broad_exception_types_detected(tmp_path: Path, clause: str):
    source = (
        "def execute_task():\n"
        "    try:\n"
        "        run()\n"
        f"    {clause}\n"
        "        handle_err()\n"
    )
    context = _parse_and_create_context(tmp_path, "task.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    broad_findings = [f for f in findings if f.rule_id == "ENT-ERR-002"]
    assert len(broad_findings) == 1
    f = broad_findings[0]
    assert f.rule_id == "ENT-ERR-002"
    assert f.line_start == 4
    assert f.symbol == "execute_task"
    assert f.severity == Severity.MEDIUM


def test_ent_err_002_specific_tuple_not_flagged(tmp_path: Path):
    source = (
        "def multi_catch():\n"
        "    try:\n"
        "        call()\n"
        "    except (KeyError, ValueError, FileNotFoundError):\n"
        "        handle_expected()\n"
    )
    context = _parse_and_create_context(tmp_path, "multi.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    broad_findings = [f for f in findings if f.rule_id == "ENT-ERR-002"]
    assert len(broad_findings) == 0


# ==============================================================================
# ENT-ERR-003: Empty Exception Handler Rule Tests
# ==============================================================================


@pytest.mark.parametrize(
    "handler_body",
    [
        "        pass\n",
        "        ...\n",
        '        """Ignore silently."""\n',
        "        pass\n        pass\n",
    ],
)
def test_ent_err_003_empty_handler_forms_detected(tmp_path: Path, handler_body: str):
    source = (
        "def discard():\n"
        "    try:\n"
        "        cleanup()\n"
        "    except OSError:\n"
        f"{handler_body}"
    )
    context = _parse_and_create_context(tmp_path, "discard.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    empty_findings = [f for f in findings if f.rule_id == "ENT-ERR-003"]
    assert len(empty_findings) == 1
    f = empty_findings[0]
    assert f.rule_id == "ENT-ERR-003"
    assert f.line_start == 4
    assert f.symbol == "discard"


def test_ent_err_003_active_handler_not_flagged(tmp_path: Path):
    source = (
        "def handle_properly():\n"
        "    try:\n"
        "        op()\n"
        "    except KeyError:\n"
        "        notify_admin()\n"
        "        raise\n"
    )
    context = _parse_and_create_context(tmp_path, "proper.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    empty_findings = [f for f in findings if f.rule_id == "ENT-ERR-003"]
    assert len(empty_findings) == 0


# ==============================================================================
# ENT-ERR-004: Silently Swallowed Exception Rule & Suppression Tests
# ==============================================================================


def test_ent_err_004_non_empty_silent_swallow_detected(tmp_path: Path):
    source = (
        "def compute():\n"
        "    try:\n"
        "        x = calculate()\n"
        "    except ValueError:\n"
        "        status = 0\n"
        "        x = 42\n"
    )
    context = _parse_and_create_context(tmp_path, "calc.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    swallowed = [f for f in findings if f.rule_id == "ENT-ERR-004"]
    assert len(swallowed) == 1
    assert swallowed[0].symbol == "compute"
    assert swallowed[0].line_start == 4


def test_ent_err_004_suppressed_when_ent_err_003_fired(tmp_path: Path):
    """ENT-ERR-004 must be suppressed if ENT-ERR-003 already fired for that line."""
    source = (
        "def ignore_err():\n"
        "    try:\n"
        "        step()\n"
        "    except KeyError:\n"
        "        pass\n"
    )
    context = _parse_and_create_context(tmp_path, "suppress.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    rule_ids = [f.rule_id for f in findings]
    # ENT-ERR-003 must be present
    assert "ENT-ERR-003" in rule_ids
    # ENT-ERR-004 must be suppressed
    assert "ENT-ERR-004" not in rule_ids


def test_ent_err_004_not_flagged_when_logged_or_raised(tmp_path: Path):
    source = (
        "def safe_calc():\n"
        "    try:\n"
        "        calc()\n"
        "    except ValueError as err:\n"
        "        logger.error('Error occurred: %s', err)\n"
        "        metrics.increment('calc_failure')\n"
    )
    context = _parse_and_create_context(tmp_path, "safe.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    swallowed = [f for f in findings if f.rule_id == "ENT-ERR-004"]
    assert len(swallowed) == 0


# ==============================================================================
# ENT-ERR-005: Generic Fallback Return Rule Tests
# ==============================================================================


@pytest.mark.parametrize(
    "ret_stmt,literal_name",
    [
        ("return None", "None"),
        ("return False", "False"),
        ("return True", "True"),
        ("return {}", "empty_dict"),
        ("return []", "empty_list"),
        ('return ""', "empty_string"),
    ],
)
def test_ent_err_005_generic_fallback_returns_detected(
    tmp_path: Path, ret_stmt: str, literal_name: str
):
    source = (
        "def fetch_data():\n"
        "    try:\n"
        "        return remote_call()\n"
        "    except ConnectionError:\n"
        f"        {ret_stmt}\n"
    )
    context = _parse_and_create_context(tmp_path, "fetch.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    fallback_findings = [f for f in findings if f.rule_id == "ENT-ERR-005"]
    assert len(fallback_findings) == 1
    f = fallback_findings[0]
    assert f.rule_id == "ENT-ERR-005"
    assert f.line_start == 5
    assert f.symbol == "fetch_data"
    assert f.metadata.get("fallback_type") == literal_name


def test_ent_err_005_meaningful_return_not_flagged(tmp_path: Path):
    source = (
        "def get_status():\n"
        "    try:\n"
        "        return query()\n"
        "    except TimeoutError:\n"
        "        return build_degraded_response(cache=True)\n"
    )
    context = _parse_and_create_context(tmp_path, "status.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    fallback_findings = [f for f in findings if f.rule_id == "ENT-ERR-005"]
    assert len(fallback_findings) == 0


# ==============================================================================
# ENT-ERR-006: Explicitly Deferred Rule Verification
# ==============================================================================


def test_ent_err_006_deferred_documentation():
    assert RULE_ERR_006_DEFERRED.rule_id == "ENT-ERR-006"
    assert "deferred" in RULE_ERR_006_DEFERRED.rationale.lower()
    assert "cross-file" in RULE_ERR_006_DEFERRED.rationale.lower()


# ==============================================================================
# Determinism, Hashing, and Deduplication Tests
# ==============================================================================


def test_deterministic_finding_id_stability():
    """Verify that finding IDs are completely deterministic 16-char hashes."""
    id1 = Finding.generate_deterministic_id(
        rule_id="ENT-ERR-001",
        file="service/auth.py",
        line_start=10,
        line_end=12,
        symbol="verify_token",
        evidence_signature="except:pass",
    )
    id2 = Finding.generate_deterministic_id(
        rule_id="ENT-ERR-001",
        file="service/auth.py",
        line_start=10,
        line_end=12,
        symbol="verify_token",
        evidence_signature="except:pass",
    )
    assert id1 == id2
    assert len(id1) == 16
    assert all(c in "0123456789abcdef" for c in id1)


def test_deterministic_findings_sorting(tmp_path: Path):
    """Findings must be deterministically sorted by (file, line_start, rule_id)."""
    source = (
        "def alpha():\n"
        "    try:\n"
        "        work()\n"
        "    except:\n"
        "        pass\n"
        "\n"
        "def beta():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        return None\n"
    )
    context = _parse_and_create_context(tmp_path, "sorting.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)

    # Check sorting order
    sort_keys = [(f.file, f.line_start, f.rule_id) for f in findings]
    assert sort_keys == sorted(sort_keys)


def test_clean_file_yields_zero_findings(tmp_path: Path):
    source = (
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n"
        "\n"
        "def divide(a: float, b: float) -> float:\n"
        "    if b == 0.0:\n"
        "        raise ValueError('Division by zero')\n"
        "    return a / b\n"
    )
    context = _parse_and_create_context(tmp_path, "math_utils.py", source)
    analyzer = ErrorHandlingDebtAnalyzer()
    findings = analyzer.analyze(context)
    assert len(findings) == 0
