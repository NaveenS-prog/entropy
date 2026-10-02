"""Phase 5 Comprehensive Unit Tests for Authentication & Authorization Debt Analyzers.

Validates all Phase 5 requirements:
- Negative tests: properly authenticated/authorized code yields 0 findings
- False-positive tests: non-route functions (CLI, utilities, tests) yield 0 findings
- Positive tests for ENT-AUTH-001, ENT-AUTH-002, ENT-AUTH-003
- Positive tests for ENT-AUTHZ-001, ENT-AUTHZ-002, ENT-AUTHZ-003
- Framework tests for FastAPI, Flask, and Django
- Determinism and deduplication tests
"""

from __future__ import annotations

from pathlib import Path

from app.analyzers.base import AnalysisContext
from app.analyzers.security.auth.authentication import AuthenticationConsistencyAnalyzer
from app.analyzers.security.auth.authorization import AuthorizationConsistencyAnalyzer
from app.analyzers.security.frameworks import FrameworkRouteDetector
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.parser.python_ast import PythonAstParser
from app.repository.discoverer import DiscoveredFile

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "auth"


def _parse_fixture(fixture_rel_path: str) -> tuple[AnalysisContext, Path]:
    abs_path = FIXTURES_DIR / fixture_rel_path
    assert abs_path.exists(), f"Fixture file not found: {abs_path}"

    source = abs_path.read_text(encoding="utf-8")
    discovered = DiscoveredFile(
        absolute_path=abs_path,
        relative_path=fixture_rel_path,
        language=SupportedLanguage.PYTHON,
        size_bytes=len(source.encode("utf-8")),
        line_count=len(source.splitlines()),
    )
    parser = PythonAstParser()
    parsed = parser.parse(discovered)
    assert parsed.is_valid is True

    context = AnalysisContext(
        repo_path=FIXTURES_DIR,
        parsed_files=[parsed],
        total_loc=discovered.line_count,
        scanned_file_count=1,
    )
    return context, abs_path


# =============================================================================
# 1. Negative Tests
# =============================================================================


def test_clean_fastapi_auth_no_findings():
    """Properly secured FastAPI endpoints must yield zero authentication/authorization findings."""
    context, _ = _parse_fixture("fastapi/clean_auth.py")

    auth_analyzer = AuthenticationConsistencyAnalyzer()
    auth_findings = auth_analyzer.analyze(context)
    assert len(auth_findings) == 0, f"Expected 0 auth findings, got: {auth_findings}"

    authz_analyzer = AuthorizationConsistencyAnalyzer()
    authz_findings = authz_analyzer.analyze(context)
    assert len(authz_findings) == 0, f"Expected 0 authz findings, got: {authz_findings}"


# =============================================================================
# 2. False Positive Tests
# =============================================================================


def test_non_routes_false_positive_prevention():
    """Non-route functions (CLI, calculators, utilities, tests) must never be flagged."""
    context, _ = _parse_fixture("false_positives/non_routes.py")
    py_ctx = context.get_valid_python_contexts()[0]

    endpoints = FrameworkRouteDetector.extract_endpoints(py_ctx)
    assert len(endpoints) == 0, f"Expected 0 endpoints extracted from non-route file, got: {endpoints}"

    auth_analyzer = AuthenticationConsistencyAnalyzer()
    assert len(auth_analyzer.analyze(context)) == 0

    authz_analyzer = AuthorizationConsistencyAnalyzer()
    assert len(authz_analyzer.analyze(context)) == 0


# =============================================================================
# 3. Positive Authentication Tests (FastAPI)
# =============================================================================


def test_ent_auth_001_unprotected_endpoint_detected():
    """ENT-AUTH-001 must detect sensitive unprotected POST /payments/charge."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")
    analyzer = AuthenticationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    f_001 = [f for f in findings if f.rule_id == "ENT-AUTH-001"]
    assert len(f_001) >= 1

    charge_finding = next((f for f in f_001 if "charge_payment" in (f.symbol or "")), None)
    assert charge_finding is not None
    assert charge_finding.category == DebtCategory.AUTHENTICATION_CONSISTENCY
    assert charge_finding.severity == Severity.MEDIUM
    assert "POST" in charge_finding.description
    assert charge_finding.evidence is not None
    assert "def charge_payment" in charge_finding.evidence.content


def test_ent_auth_002_inconsistent_authentication_detected():
    """ENT-AUTH-002 must detect inconsistent /account/history within the /account group."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")
    analyzer = AuthenticationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    f_002 = [f for f in findings if f.rule_id == "ENT-AUTH-002"]
    assert len(f_002) >= 1

    history_finding = next((f for f in f_002 if "account_history" in (f.symbol or "")), None)
    assert history_finding is not None
    assert history_finding.category == DebtCategory.AUTHENTICATION_CONSISTENCY
    assert history_finding.severity == Severity.MEDIUM
    assert history_finding.confidence == Confidence.HIGH
    assert "/account/overview" in history_finding.description or "account_overview" in history_finding.description


def test_ent_auth_003_duplicated_authentication_detected():
    """ENT-AUTH-003 must detect repeated inline header extraction in token_a and token_b."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")
    analyzer = AuthenticationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    f_003 = [f for f in findings if f.rule_id == "ENT-AUTH-003"]
    assert len(f_003) >= 2

    symbols = {f.symbol for f in f_003}
    assert "verify_token_a" in symbols
    assert "verify_token_b" in symbols

    for f in f_003:
        assert f.category == DebtCategory.AUTHENTICATION_CONSISTENCY
        assert f.severity == Severity.LOW
        assert "duplicated across multiple handlers" in f.description


# =============================================================================
# 4. Positive Authorization Tests (FastAPI)
# =============================================================================


def test_ent_authz_001_missing_authorization_detected():
    """ENT-AUTHZ-001 must detect missing role check on privileged /system/reset."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")
    analyzer = AuthorizationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    f_001 = [f for f in findings if f.rule_id == "ENT-AUTHZ-001"]
    assert len(f_001) >= 1

    reset_finding = next((f for f in f_001 if "system_reset" in (f.symbol or "")), None)
    assert reset_finding is not None
    assert reset_finding.category == DebtCategory.AUTHORIZATION_CONSISTENCY
    assert reset_finding.severity in (Severity.MEDIUM, Severity.HIGH)
    assert "Privileged endpoint" in reset_finding.description


def test_ent_authz_002_inconsistent_authorization_detected():
    """ENT-AUTHZ-002 must detect inconsistent /admin/config within the admin group."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")
    analyzer = AuthorizationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    f_002 = [f for f in findings if f.rule_id == "ENT-AUTHZ-002"]
    assert len(f_002) >= 1

    config_finding = next((f for f in f_002 if "get_admin_config" in (f.symbol or "")), None)
    assert config_finding is not None
    assert config_finding.category == DebtCategory.AUTHORIZATION_CONSISTENCY
    assert config_finding.severity == Severity.MEDIUM
    assert config_finding.confidence == Confidence.HIGH
    assert "admin" in config_finding.description


def test_ent_authz_003_duplicated_authorization_detected():
    """ENT-AUTHZ-003 must detect repeated inline role check in run_job_a and run_job_b."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")
    analyzer = AuthorizationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    f_003 = [f for f in findings if f.rule_id == "ENT-AUTHZ-003"]
    assert len(f_003) >= 2

    symbols = {f.symbol for f in f_003}
    assert "run_job_a" in symbols
    assert "run_job_b" in symbols

    for f in f_003:
        assert f.category == DebtCategory.AUTHORIZATION_CONSISTENCY
        assert f.severity == Severity.LOW
        assert "duplicated across multiple handlers" in f.description


# =============================================================================
# 5. Framework Verification (Flask & Django)
# =============================================================================


def test_flask_routes_analysis():
    """Flask framework routes, login_required decorators, and blueprints must be correctly analyzed."""
    context, _ = _parse_fixture("flask/flask_routes.py")

    auth_analyzer = AuthenticationConsistencyAnalyzer()
    findings = auth_analyzer.analyze(context)

    # 1. /profile with @login_required should NOT be flagged
    assert not any(f.symbol == "user_profile" for f in findings)

    # 2. /admin/purge should be flagged as unprotected (ENT-AUTH-001)
    purge_finding = next((f for f in findings if f.symbol == "purge_system"), None)
    assert purge_finding is not None
    assert purge_finding.rule_id == "ENT-AUTH-001"

    # 3. /dashboard/raw_dump should be flagged as inconsistent (ENT-AUTH-002)
    inconsistent_dash = next((f for f in findings if f.symbol == "dash_raw_dump"), None)
    assert inconsistent_dash is not None
    assert inconsistent_dash.rule_id == "ENT-AUTH-002"


def test_django_views_analysis():
    """Django framework function views and class-based views must be correctly analyzed."""
    context, _ = _parse_fixture("django/django_views.py")

    auth_analyzer = AuthenticationConsistencyAnalyzer()
    auth_findings = auth_analyzer.analyze(context)

    # 1. Clean views with login_required or permission_classes must not be flagged
    assert not any(f.symbol == "user_account_view" for f in auth_findings)
    assert not any("SecureAdminViewSet" in (f.symbol or "") for f in auth_findings)

    # 2. UnprotectedAdminViewSet.delete must be flagged
    unprotected_cbv = next((f for f in auth_findings if "UnprotectedAdminViewSet" in (f.symbol or "")), None)
    assert unprotected_cbv is not None
    assert unprotected_cbv.rule_id in ("ENT-AUTH-001", "ENT-AUTH-002")


# =============================================================================
# 6. Determinism & Deduplication Tests
# =============================================================================


def test_finding_id_stability():
    """Repeated analysis invocations on identical input must produce identical finding IDs and order."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")

    analyzer = AuthenticationConsistencyAnalyzer()
    run1 = analyzer.analyze(context)
    run2 = analyzer.analyze(context)

    assert len(run1) == len(run2)
    for f1, f2 in zip(run1, run2, strict=True):
        assert f1.id == f2.id
        assert f1.rule_id == f2.rule_id
        assert f1.file == f2.file
        assert f1.line_start == f2.line_start
        assert f1.symbol == f2.symbol
        assert f1.fingerprint == f2.fingerprint


def test_suppression_of_unprotected_when_inconsistent():
    """When ENT-AUTH-002 flags an inconsistent route, ENT-AUTH-001 must be suppressed on that route."""
    context, _ = _parse_fixture("fastapi/unprotected_and_inconsistent.py")
    analyzer = AuthenticationConsistencyAnalyzer()
    findings = analyzer.analyze(context)

    # /account/history should ONLY have ENT-AUTH-002, not both ENT-AUTH-001 and ENT-AUTH-002
    history_rules = [f.rule_id for f in findings if "account_history" in (f.symbol or "")]
    assert "ENT-AUTH-002" in history_rules
    assert "ENT-AUTH-001" not in history_rules
