"""Phase 3 Unit Tests: JavaScript & TypeScript Security Coverage.

Validates:
1. JS/TS Route Detection: Express, Fastify, Next.js App Router, Next.js Pages Router.
2. Authentication Consistency: ENT-AUTH-001, ENT-AUTH-002, ENT-AUTH-003.
3. Authorization Consistency: ENT-AUTHZ-001, ENT-AUTHZ-002, ENT-AUTHZ-003.
4. False Positives: Protected routes with middleware or inline checks, public routes.
5. Input Validation Sink Gap: db.run('DELETE ... WHERE id=' + req.body.id) flagged; parameterized not flagged.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.analyzers.base import AnalysisContext
from app.analyzers.jsts_context import JSTSASTContext
from app.analyzers.jsts_rules.authentication import (
    JSDuplicatedAuthenticationRule,
    JSInconsistentAuthenticationRule,
    JSUnprotectedEndpointRule,
)
from app.analyzers.jsts_rules.authorization import (
    JSDuplicatedAuthorizationRule,
    JSInconsistentAuthorizationRule,
    JSMissingAuthorizationRule,
)
from app.analyzers.jsts_rules.input_validation import JSUnvalidatedInputRule
from app.analyzers.security.auth.authentication import AuthenticationConsistencyAnalyzer
from app.analyzers.security.auth.authorization import AuthorizationConsistencyAnalyzer
from app.models.domain.enums import DebtCategory, Severity, SupportedLanguage
from app.parser.jsts.parser import JSTSParser

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "jsts_security"


def _parse_js(file_path: Path, rel_path: str = "app.js", lang: SupportedLanguage = SupportedLanguage.JAVASCRIPT) -> JSTSASTContext:
    parser = JSTSParser()
    unit = parser.parse_file(file_path, rel_path, lang)
    return JSTSASTContext(unit)


class TestJSTSRouteDetection:
    """Test web framework route detection across Express, Fastify, and Next.js."""

    def test_express_route_detection(self):
        ctx = _parse_js(FIXTURES_DIR / "express_unprotected.js")
        routes = ctx.get_routes()

        assert len(routes) == 3
        paths = {r.path for r in routes}
        methods = {(r.http_method, r.path) for r in routes}

        assert paths == {"/admin/delete-user", "/admin/export", "/payments/refund"}
        assert ("POST", "/admin/delete-user") in methods
        assert ("GET", "/admin/export") in methods
        assert ("POST", "/payments/refund") in methods
        assert all(r.framework == "express" for r in routes)

    def test_express_middleware_extraction(self):
        ctx = _parse_js(FIXTURES_DIR / "express_protected.js")
        routes = ctx.get_routes()

        routes_by_path = {r.path: r for r in routes}
        admin_route = routes_by_path["/admin/delete-user"]
        refund_route = routes_by_path["/payments/refund"]

        # Directly passed middleware
        assert "authMiddleware" in admin_route.middleware
        assert "requireAdmin" in admin_route.middleware

        # Array-passed middleware [authMiddleware, requireAdmin]
        assert "authMiddleware" in refund_route.middleware
        assert "requireAdmin" in refund_route.middleware

    def test_fastify_route_detection(self):
        ctx = _parse_js(FIXTURES_DIR / "fastify_app.js")
        routes = ctx.get_routes()

        assert len(routes) == 2
        routes_by_path = {r.path: r for r in routes}

        # Route defined via fastify.route({ method: 'DELETE', url: '/admin/delete-user', ... })
        assert "/admin/delete-user" in routes_by_path
        route_obj = routes_by_path["/admin/delete-user"]
        assert route_obj.http_method == "DELETE"
        assert route_obj.framework == "fastify"

        # Route defined with preHandler
        assert "/admin/stats" in routes_by_path
        stats_route = routes_by_path["/admin/stats"]
        assert stats_route.http_method == "GET"
        assert "authGuard" in stats_route.middleware

    def test_nextjs_app_router_route_detection(self):
        content = """
export async function GET(request) {
    return Response.json({ users: [] });
}

export async function DELETE(request) {
    return Response.json({ deleted: true });
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "app" / "api" / "admin" / "users" / "route.ts"
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)

            ctx = _parse_js(file_path, "app/api/admin/users/route.ts", SupportedLanguage.TYPESCRIPT)
            routes = ctx.get_routes()

            assert len(routes) == 2
            methods = {r.http_method for r in routes}
            assert methods == {"GET", "DELETE"}
            assert all(r.path == "/api/admin/users" for r in routes)
            assert all(r.framework == "nextjs" for r in routes)

    def test_nextjs_pages_router_route_detection(self):
        content = """
export default function handler(req, res) {
    res.status(200).json({ status: "ok" });
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "pages" / "api" / "admin" / "export.ts"
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)

            ctx = _parse_js(file_path, "pages/api/admin/export.ts", SupportedLanguage.TYPESCRIPT)
            routes = ctx.get_routes()

            assert len(routes) == 1
            route = routes[0]
            assert route.path == "/api/admin/export"
            assert route.http_method == "ALL"
            assert route.framework == "nextjs"


class TestJSTSAuthenticationRules:
    """Test ENT-AUTH-001, ENT-AUTH-002, ENT-AUTH-003 on JS/TS applications."""

    def test_unprotected_sensitive_endpoints_flagged_with_escalation(self):
        ctx = _parse_js(FIXTURES_DIR / "express_unprotected.js")
        rule = JSUnprotectedEndpointRule()
        findings = rule.analyze(ctx)

        assert len(findings) == 3
        for f in findings:
            assert f.rule_id == "ENT-AUTH-001"
            assert f.category == DebtCategory.AUTHENTICATION_CONSISTENCY

        findings_by_path = {f.metadata["route_path"]: f for f in findings}

        # Mutating endpoints escalate to CRITICAL
        assert findings_by_path["/admin/delete-user"].severity == Severity.CRITICAL
        assert findings_by_path["/payments/refund"].severity == Severity.CRITICAL

        # Read endpoint on sensitive route is HIGH
        assert findings_by_path["/admin/export"].severity == Severity.HIGH

    def test_protected_and_public_endpoints_not_flagged(self):
        """False-positive fixture: Protected endpoints and public routes must not be flagged."""
        ctx = _parse_js(FIXTURES_DIR / "express_protected.js")
        rule = JSUnprotectedEndpointRule()
        findings = rule.analyze(ctx)

        # /health (public), /login (public), /admin/delete-user (authMiddleware),
        # /payments/refund ([authMiddleware, requireAdmin]), /user/profile (req.user)
        assert len(findings) == 0

    def test_inconsistent_authentication_in_route_group(self):
        ctx = _parse_js(FIXTURES_DIR / "express_inconsistent.js")
        rule = JSInconsistentAuthenticationRule()
        findings = rule.analyze(ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "ENT-AUTH-002"
        assert finding.metadata["route_group"] == "/admin"
        assert finding.metadata["unprotected_route"] == "/admin/delete-user"
        assert finding.severity == Severity.CRITICAL

    def test_duplicated_authentication_logic(self):
        content = """
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.get('/api/users', (req, res) => {
    const token = req.headers.authorization;
    jwt.verify(token, 'secret');
    res.json([]);
});

app.post('/api/orders', (req, res) => {
    const token = req.headers.authorization;
    jwt.verify(token, 'secret');
    res.json({ id: 1 });
});
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "app.js"
            f.write_text(content)
            ctx = _parse_js(f)
            rule = JSDuplicatedAuthenticationRule()
            findings = rule.analyze(ctx)

            assert len(findings) == 1
            assert findings[0].rule_id == "ENT-AUTH-003"


class TestJSTSAuthorizationRules:
    """Test ENT-AUTHZ-001, ENT-AUTHZ-002, ENT-AUTHZ-003 on JS/TS applications."""

    def test_missing_authorization_flagged_with_escalation(self):
        ctx = _parse_js(FIXTURES_DIR / "express_unprotected.js")
        rule = JSMissingAuthorizationRule()
        findings = rule.analyze(ctx)

        # /admin/delete-user, /admin/export, /payments/refund are privileged
        assert len(findings) == 3
        for f in findings:
            assert f.rule_id == "ENT-AUTHZ-001"
            assert f.category == DebtCategory.AUTHORIZATION_CONSISTENCY

        findings_by_path = {f.metadata["route_path"]: f for f in findings}
        assert findings_by_path["/admin/delete-user"].severity == Severity.CRITICAL
        assert findings_by_path["/payments/refund"].severity == Severity.CRITICAL
        assert findings_by_path["/admin/export"].severity == Severity.HIGH

    def test_authorized_endpoints_not_flagged(self):
        """False-positive fixture: Endpoints with role guards or permission checks must not be flagged."""
        ctx = _parse_js(FIXTURES_DIR / "express_protected.js")
        rule = JSMissingAuthorizationRule()
        findings = rule.analyze(ctx)

        assert len(findings) == 0

    def test_inconsistent_authorization_in_route_group(self):
        ctx = _parse_js(FIXTURES_DIR / "express_inconsistent.js")
        rule = JSInconsistentAuthorizationRule()
        findings = rule.analyze(ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "ENT-AUTHZ-002"
        assert finding.metadata["route_group"] == "/admin"
        assert finding.metadata["unauthorized_route"] == "/admin/delete-user"

    def test_duplicated_authorization_logic(self):
        content = """
const express = require('express');
const app = express();

app.get('/admin/users', (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).send();
    res.json([]);
});

app.post('/admin/settings', (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).send();
    res.json({ updated: true });
});
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "app.js"
            f.write_text(content)
            ctx = _parse_js(f)
            rule = JSDuplicatedAuthorizationRule()
            findings = rule.analyze(ctx)

            assert len(findings) == 1
            assert findings[0].rule_id == "ENT-AUTHZ-003"


class TestJSTSInputValidationGap:
    """Test fix for db.run('DELETE ... WHERE id=' + req.body.id)."""

    def test_db_run_concatenation_flagged(self):
        ctx = _parse_js(FIXTURES_DIR / "input_validation_db_run.js")
        rule = JSUnvalidatedInputRule()
        findings = rule.analyze(ctx)

        # /api/delete should be flagged; /api/safe-delete uses '?' so should NOT be flagged
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "ENT-INPUT-JS-001"
        assert finding.severity == Severity.HIGH
        assert "DELETE FROM users WHERE id=" in finding.description
        assert "req.body.id" in finding.description


class TestSecurityAnalyzersIntegration:
    """Test full Analyzer execution on JS/TS context."""

    def test_authentication_analyzer_runs_on_jsts(self):
        ctx = _parse_js(FIXTURES_DIR / "express_unprotected.js")
        context = AnalysisContext.from_python_units(
            repo_path=FIXTURES_DIR,
            units=[],
            jsts_units=[ctx.unit],
        )

        analyzer = AuthenticationConsistencyAnalyzer()
        assert SupportedLanguage.JAVASCRIPT in analyzer.supported_languages
        assert SupportedLanguage.TYPESCRIPT in analyzer.supported_languages

        findings = analyzer.analyze(context)
        assert len(findings) == 3
        assert all(f.category == DebtCategory.AUTHENTICATION_CONSISTENCY for f in findings)

    def test_authorization_analyzer_runs_on_jsts(self):
        ctx = _parse_js(FIXTURES_DIR / "express_unprotected.js")
        context = AnalysisContext.from_python_units(
            repo_path=FIXTURES_DIR,
            units=[],
            jsts_units=[ctx.unit],
        )

        analyzer = AuthorizationConsistencyAnalyzer()
        assert SupportedLanguage.JAVASCRIPT in analyzer.supported_languages
        assert SupportedLanguage.TYPESCRIPT in analyzer.supported_languages

        findings = analyzer.analyze(context)
        assert len(findings) == 3
        assert all(f.category == DebtCategory.AUTHORIZATION_CONSISTENCY for f in findings)
