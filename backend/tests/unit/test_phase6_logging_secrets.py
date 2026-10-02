"""Unit tests for Phase 6 Logging and Secret Handling Debt Analyzer."""

from pathlib import Path

from app.analyzers.base import AnalysisContext
from app.analyzers.security.logging_secrets import LoggingAndSecretsAnalyzer
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.parser.python_ast import PythonAstParser
from app.repository.discoverer import DiscoveredFile

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "logging_secrets"


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


def test_clean_logging_secrets_no_findings():
    """Safe runtime environment variables and non-sensitive logging yield 0 findings."""
    clean_file = FIXTURES_DIR / "clean_logging_secrets.py"
    context = _create_context_for_file(clean_file)

    analyzer = LoggingAndSecretsAnalyzer()
    findings = analyzer.analyze(context)

    assert len(findings) == 0, f"Expected 0 findings for clean file, got {findings}"


def test_false_positives_safe_logs_no_findings():
    """Informational log messages mentioning 'password'/'token' and placeholder constants yield 0 findings."""
    fp_file = FIXTURES_DIR / "false_positives" / "safe_logs.py"
    context = _create_context_for_file(fp_file)

    analyzer = LoggingAndSecretsAnalyzer()
    findings = analyzer.analyze(context)

    assert len(findings) == 0, f"Expected 0 findings for safe logs fixture, got {findings}"


def test_ent_log_001_sensitive_data_in_logs_detected():
    """Detect sensitive variables (password, auth_token) passed or formatted into logs."""
    debt_file = FIXTURES_DIR / "sensitive_logging_and_secrets.py"
    context = _create_context_for_file(debt_file)

    analyzer = LoggingAndSecretsAnalyzer()
    findings = analyzer.analyze(context)

    log_001 = [f for f in findings if f.rule_id == "ENT-LOG-001"]
    assert len(log_001) >= 2

    pwd_finding = next(f for f in log_001 if "password" in f.title.lower())
    assert pwd_finding.category == DebtCategory.LOGGING_AND_SECRETS
    assert pwd_finding.severity == Severity.HIGH
    assert pwd_finding.confidence == Confidence.HIGH
    assert "password" in pwd_finding.evidence.content

    token_finding = next(f for f in log_001 if "token" in f.title.lower())
    assert token_finding.severity == Severity.HIGH
    assert "token" in token_finding.evidence.content


def test_ent_log_002_hardcoded_secrets_detected():
    """Detect hardcoded live secret prefixes and high-entropy credentials."""
    debt_file = FIXTURES_DIR / "sensitive_logging_and_secrets.py"
    context = _create_context_for_file(debt_file)

    analyzer = LoggingAndSecretsAnalyzer()
    findings = analyzer.analyze(context)

    log_002 = [f for f in findings if f.rule_id == "ENT-LOG-002"]
    assert len(log_002) >= 2

    stripe_finding = next(f for f in log_002 if f.symbol == "STRIPE_API_KEY")
    assert stripe_finding.severity == Severity.HIGH
    assert stripe_finding.confidence == Confidence.HIGH
    assert "sk_live_" in stripe_finding.evidence.content

    pwd_finding = next(f for f in log_002 if f.symbol == "DB_PASSWORD")
    assert pwd_finding.severity == Severity.HIGH
    assert "SuperSecret" in pwd_finding.evidence.content


def test_ent_log_003_sensitive_objects_in_logs_detected():
    """Detect whole request and header objects logged directly."""
    debt_file = FIXTURES_DIR / "sensitive_logging_and_secrets.py"
    context = _create_context_for_file(debt_file)

    analyzer = LoggingAndSecretsAnalyzer()
    findings = analyzer.analyze(context)

    log_003 = [f for f in findings if f.rule_id == "ENT-LOG-003"]
    assert len(log_003) >= 2

    req_finding = next(f for f in log_003 if "request" in f.title.lower())
    assert req_finding.severity == Severity.MEDIUM
    assert req_finding.confidence == Confidence.HIGH

    hdr_finding = next(f for f in log_003 if "header" in f.title.lower())
    assert hdr_finding.severity == Severity.MEDIUM


def test_ent_log_004_inconsistent_secret_handling_detected():
    """Detect insecure hardcoded fallback literal in environment lookup."""
    debt_file = FIXTURES_DIR / "sensitive_logging_and_secrets.py"
    context = _create_context_for_file(debt_file)

    analyzer = LoggingAndSecretsAnalyzer()
    findings = analyzer.analyze(context)

    log_004 = [f for f in findings if f.rule_id == "ENT-LOG-004"]
    assert len(log_004) == 1
    fallback_finding = log_004[0]
    assert fallback_finding.severity == Severity.MEDIUM
    assert "JWT_SECRET" in fallback_finding.evidence.content or "JWT_SECRET" in fallback_finding.title
    assert "insecure_fallback" in fallback_finding.evidence.content


def test_finding_id_stability():
    """Verify that finding IDs and fingerprints are deterministic across invocations."""
    debt_file = FIXTURES_DIR / "sensitive_logging_and_secrets.py"
    context1 = _create_context_for_file(debt_file)
    context2 = _create_context_for_file(debt_file)

    analyzer = LoggingAndSecretsAnalyzer()
    f1 = analyzer.analyze(context1)
    f2 = analyzer.analyze(context2)

    assert len(f1) == len(f2)
    assert [f.fingerprint for f in f1] == [f.fingerprint for f in f2]
    assert [f.id for f in f1] == [f.id for f in f2]
