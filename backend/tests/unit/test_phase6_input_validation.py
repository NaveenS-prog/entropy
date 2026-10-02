"""Unit tests for Phase 6 Input Validation Consistency Analyzer."""

from pathlib import Path

from app.analyzers.base import AnalysisContext
from app.analyzers.security.validation import InputValidationConsistencyAnalyzer
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.parser.python_ast import PythonAstParser
from app.repository.discoverer import DiscoveredFile

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "validation"


def _create_context_for_file(file_path: Path) -> AnalysisContext:
    source = file_path.read_text(encoding="utf-8")
    discovered = DiscoveredFile(
        absolute_path=file_path,
        relative_path=file_path.name,
        language=SupportedLanguage.PYTHON,
        size_bytes=len(source.encode("utf-8")),
        line_count=len(source.splitlines()),
    )
    parser = PythonAstParser()
    parsed_file = parser.parse(discovered)
    assert parsed_file.is_valid is True
    return AnalysisContext(
        repo_path=file_path.parent,
        parsed_files=[parsed_file],
        total_loc=discovered.line_count or 0,
        scanned_file_count=1,
    )


def test_clean_validation_no_findings():
    """Clean Pydantic schemas, typed parameters, and Query constraints yield 0 findings."""
    clean_file = FIXTURES_DIR / "clean_validation.py"
    context = _create_context_for_file(clean_file)

    analyzer = InputValidationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    assert len(findings) == 0, f"Expected 0 findings for clean file, got {findings}"


def test_false_positives_safe_inputs_no_findings():
    """Internal functions, parameterized SQL queries, and safe subprocess calls yield 0 findings."""
    fp_file = FIXTURES_DIR / "false_positives" / "safe_inputs.py"
    context = _create_context_for_file(fp_file)

    analyzer = InputValidationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    assert len(findings) == 0, f"Expected 0 findings for safe inputs fixture, got {findings}"


def test_ent_input_001_unvalidated_input_detected():
    """Detect unvalidated external input in a sensitive/mutating endpoint."""
    debt_file = FIXTURES_DIR / "unvalidated_and_inconsistent.py"
    context = _create_context_for_file(debt_file)

    analyzer = InputValidationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    input_001 = [f for f in findings if f.rule_id == "ENT-INPUT-001"]
    assert len(input_001) >= 1
    charge_finding = next(f for f in input_001 if f.symbol == "charge_customer")
    assert charge_finding.category == DebtCategory.INPUT_VALIDATION
    assert charge_finding.severity == Severity.MEDIUM
    assert "charge" in charge_finding.title.lower() or "charge" in charge_finding.description.lower()
    assert charge_finding.evidence != ""


def test_ent_input_002_inconsistent_input_validation_detected():
    """Detect inconsistent input validation between sibling endpoints in the same group."""
    debt_file = FIXTURES_DIR / "unvalidated_and_inconsistent.py"
    context = _create_context_for_file(debt_file)

    analyzer = InputValidationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    input_002 = [f for f in findings if f.rule_id == "ENT-INPUT-002"]
    assert len(input_002) == 1
    inconsistent = input_002[0]
    assert inconsistent.symbol == "profile_update"
    assert inconsistent.severity == Severity.MEDIUM
    assert inconsistent.confidence == Confidence.HIGH
    assert "inconsistent" in inconsistent.title.lower()
    assert "register_user" in inconsistent.description


def test_ent_input_002_suppresses_ent_input_001():
    """Verify that ENT-INPUT-002 suppresses ENT-INPUT-001 on the same endpoint."""
    debt_file = FIXTURES_DIR / "unvalidated_and_inconsistent.py"
    context = _create_context_for_file(debt_file)

    analyzer = InputValidationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    # profile_update must only have ENT-INPUT-002, NOT ENT-INPUT-001
    profile_update_rules = [f.rule_id for f in findings if f.symbol == "profile_update"]
    assert "ENT-INPUT-002" in profile_update_rules
    assert "ENT-INPUT-001" not in profile_update_rules


def test_ent_input_003_unsafe_direct_input_usage_detected():
    """Detect external input flowing directly into SQL queries and subprocess commands."""
    debt_file = FIXTURES_DIR / "unvalidated_and_inconsistent.py"
    context = _create_context_for_file(debt_file)

    analyzer = InputValidationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    input_003 = [f for f in findings if f.rule_id == "ENT-INPUT-003"]
    assert len(input_003) >= 2

    sql_finding = next(f for f in input_003 if f.symbol == "search_items")
    assert sql_finding.severity == Severity.HIGH
    assert "sql" in sql_finding.title.lower() or "sql" in sql_finding.description.lower()
    assert "SELECT" in sql_finding.evidence.content

    subproc_finding = next(f for f in input_003 if f.symbol == "ping_host")
    assert subproc_finding.severity == Severity.HIGH
    assert "subprocess" in subproc_finding.title.lower() or "command" in subproc_finding.description.lower()
    assert "ping" in subproc_finding.evidence.content


def test_finding_id_stability():
    """Verify that finding IDs and fingerprints are deterministic across invocations."""
    debt_file = FIXTURES_DIR / "unvalidated_and_inconsistent.py"
    context1 = _create_context_for_file(debt_file)
    context2 = _create_context_for_file(debt_file)

    analyzer = InputValidationConsistencyAnalyzer()
    f1 = analyzer.analyze(context1)
    f2 = analyzer.analyze(context2)

    assert len(f1) == len(f2)
    assert [f.fingerprint for f in f1] == [f.fingerprint for f in f2]
    assert [f.id for f in f1] == [f.id for f in f2]
