"""Phase 3 Regression Tests: Intentionally Public Endpoints and Severity Floor Constraints.

Validates:
1. Endpoints matching intentionally public patterns (e.g. /login/access-token, /reset-password/,
   /healthz, /auth/callback) are treated as intentionally public and not reported as unprotected.
2. In JS/TS and Python, endpoints with no sensitive response data have their severity dropped by one level.
3. FastAPI template login/reset routes produce no CRITICAL findings.
4. Truly unprotected /admin mutating route triggers the severity floor and names the finding that triggered it.
5. High-confidence CRITICAL findings located in test or example paths do NOT trigger the severity floor.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import Finding
from app.scoring.entropy_scorer import entropy_scorer
from app.scoring.weights import is_intentionally_public_endpoint
from app.services.scan_service import ScanService


def test_is_intentionally_public_endpoint_matching():
    """Verify standard intentionally public terms in route paths and handler names."""
    assert is_intentionally_public_endpoint("/api/v1/login/access-token", "login_access_token")
    assert is_intentionally_public_endpoint("/reset-password", "reset_password")
    assert is_intentionally_public_endpoint("/healthz", "healthz")
    assert is_intentionally_public_endpoint("/oauth/callback", "oauth_callback")
    assert is_intentionally_public_endpoint("/metrics", "prometheus_metrics")
    assert is_intentionally_public_endpoint("/docs", "swagger_ui")
    assert is_intentionally_public_endpoint("/openapi.json", "openapi")

    # Non-public endpoints
    assert not is_intentionally_public_endpoint("/api/v1/admin/users", "list_users")
    assert not is_intentionally_public_endpoint("/payments/charge", "charge_payment")
    assert not is_intentionally_public_endpoint("/system/reboot", "reboot")


def test_fastapi_template_login_and_reset_produce_no_critical():
    """FastAPI template login/access-token and reset-password routes must not produce CRITICAL findings."""
    code = '''from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter()

class Token(BaseModel):
    access_token: str
    token_type: str

class Message(BaseModel):
    message: str

@router.post("/login/access-token", response_model=Token)
def login_access_token():
    return Token(access_token="fake-token", token_type="bearer")

@router.post("/reset-password/", response_model=Message)
def reset_password():
    return Message(message="Password updated successfully")
'''
    service = ScanService()
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "auth.py").write_text(code)
        scan = service.execute_scan(Path(tmpdir))

        critical_findings = [f for f in scan.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0, f"Expected no CRITICAL findings, got: {critical_findings}"

        unprotected_auth_findings = [
            f for f in scan.findings
            if f.rule_id == "ENT-AUTH-001" and any(route in f.description for route in ("/login", "/reset-password"))
        ]
        assert len(unprotected_auth_findings) == 0, "Public routes must not be flagged by ENT-AUTH-001"


def test_truly_unprotected_admin_route_triggers_severity_floor_and_names_finding():
    """A truly unprotected mutating /admin route triggers the floor and names the triggering finding."""
    admin_code = '''from fastapi import FastAPI
app = FastAPI()

@app.post("/admin/system/reset-credentials")
def reset_admin_credentials():
    return {"api_key": "new_secret_key", "password_hash": "..."}
'''
    service = ScanService()
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "admin.py").write_text(admin_code)
        scan = service.execute_scan(Path(tmpdir))

        assert scan.score is not None
        assert scan.score.severity_floor_applied is True
        assert scan.score.total_score >= 61
        assert scan.score.floor_reason is not None

        # Must name the finding ID and rule ID
        crit_finding = next(
            (f for f in scan.findings if f.severity == Severity.CRITICAL and f.confidence == Confidence.HIGH),
            None,
        )
        assert crit_finding is not None
        assert crit_finding.id in scan.score.floor_reason
        assert "ENT-AUTH-001" in scan.score.floor_reason
        assert "triggered by" in scan.score.floor_reason


def test_severity_floor_excludes_test_and_example_paths():
    """High confidence CRITICAL findings in test or example paths must not trigger the severity floor."""
    from app.models.domain.finding import CodeEvidence

    test_finding = Finding(
        id="finding-test-1234",
        category=DebtCategory.AUTHENTICATION_CONSISTENCY,
        rule_id="ENT-AUTH-001",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file="tests/test_mock_admin.py",
        line_start=10,
        line_end=15,
        title="Unprotected Endpoint in Test",
        description="Test mock endpoint without auth",
        evidence=CodeEvidence(content="def mock_endpoint(): pass", line_start=10, line_end=15),
        impact="Test impact",
        recommendation="Test recommendation",
        fingerprint="test-fp-1234",
    )
    example_finding = Finding(
        id="finding-example-5678",
        category=DebtCategory.AUTHENTICATION_CONSISTENCY,
        rule_id="ENT-AUTH-001",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file="examples/sample_admin.py",
        line_start=5,
        line_end=10,
        title="Unprotected Endpoint in Example",
        description="Example demo endpoint without auth",
        evidence=CodeEvidence(content="def example_endpoint(): pass", line_start=5, line_end=10),
        impact="Example impact",
        recommendation="Example recommendation",
        fingerprint="example-fp-5678",
    )

    res = entropy_scorer.calculate_score(
        findings=[test_finding, example_finding],
        total_loc=5000,
        analyzed_files=10,
        analyzed_categories=[DebtCategory.AUTHENTICATION_CONSISTENCY],
    )

    # Floor should NOT be applied because findings are in test and example paths
    assert res.severity_floor_applied is False
    assert res.floor_reason is None
