"""Phase 1 Regression Tests: Public-Name Bypass Prevention and Anchored Matching.

Verifies:
1. Anchored matching on full normalized route path with generic prefix stripping (up to 2 segments).
2. Parameter wildcard handling ({param}, :param, [param]).
3. Deny override: sensitive/administrative terms (admin, internal, manage, root, etc.) in any
   path segment or handler name unconditionally prevent public exemption.
4. State-changing HTTP method validation (POST/PUT/PATCH/DELETE) against explicit allowlist.
5. Handler name is a hint only (may lower confidence, never removes a finding).
6. Explainable audit trail in finding metadata and public_endpoints_skipped count in coverage.
7. Verification across Python (FastAPI) and JS/TS (Express, Fastify, NestJS).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.analyzers.context import PythonASTContext
from app.analyzers.jsts_context import JSTSASTContext
from app.analyzers.jsts_rules.authentication import JSUnprotectedEndpointRule
from app.analyzers.jsts_rules.authorization import JSMissingAuthorizationRule
from app.analyzers.security.auth.rules import (
    PotentiallyMissingAuthorizationRule,
    PotentiallyUnprotectedEndpointRule,
)
from app.models.domain.enums import SupportedLanguage
from app.parser.jsts.parser import JSTSParser
from app.parser.python.parser import PythonParser
from app.scoring.weights import (
    is_intentionally_public_endpoint,
    match_intentionally_public_endpoint,
)
from app.services.scan_service import ScanService


class TestAnchoredPublicMatchingUnit:
    """Direct unit tests for match_intentionally_public_endpoint and is_intentionally_public_endpoint."""

    def test_known_public_patterns_and_generic_prefixes(self):
        # Base patterns
        assert is_intentionally_public_endpoint("/login", "login", http_method="POST")
        assert is_intentionally_public_endpoint("/logout", "logout", http_method="POST")
        assert is_intentionally_public_endpoint("/signup", "signup", http_method="POST")
        assert is_intentionally_public_endpoint("/register", "register", http_method="POST")
        assert is_intentionally_public_endpoint("/token", "token", http_method="POST")
        assert is_intentionally_public_endpoint("/refresh", "refresh", http_method="POST")
        assert is_intentionally_public_endpoint("/reset-password", "reset_password", http_method="POST")
        assert is_intentionally_public_endpoint("/forgot-password", "forgot_password", http_method="POST")
        assert is_intentionally_public_endpoint("/health", "health", http_method="GET")
        assert is_intentionally_public_endpoint("/healthz", "healthz", http_method="GET")
        assert is_intentionally_public_endpoint("/ping", "ping", http_method="GET")
        assert is_intentionally_public_endpoint("/status", "status", http_method="GET")
        assert is_intentionally_public_endpoint("/docs", "docs", http_method="GET")
        assert is_intentionally_public_endpoint("/openapi.json", "openapi", http_method="GET")
        assert is_intentionally_public_endpoint("/metrics", "metrics", http_method="GET")

        # FastAPI template routes
        assert is_intentionally_public_endpoint("/login/access-token", "login_access_token", http_method="POST")
        assert is_intentionally_public_endpoint("/password-recovery/{email}", "recover_pwd", http_method="POST")
        assert is_intentionally_public_endpoint("/reset-password/", "reset_pwd", http_method="POST")

        # Generic prefixes (up to two segments: api, v1, v2, auth, oauth, oauth2, accounts, public)
        assert is_intentionally_public_endpoint("/api/login", "login", http_method="POST")
        assert is_intentionally_public_endpoint("/api/v1/login", "login", http_method="POST")
        assert is_intentionally_public_endpoint("/api/v2/health", "health", http_method="GET")
        assert is_intentionally_public_endpoint("/auth/login", "login", http_method="POST")
        assert is_intentionally_public_endpoint("/oauth/token", "token", http_method="POST")
        assert is_intentionally_public_endpoint("/oauth2/token", "token", http_method="POST")
        assert is_intentionally_public_endpoint("/public/metrics", "metrics", http_method="GET")

    def test_wildcard_segments_matching(self):
        # Python format {param}
        res1 = match_intentionally_public_endpoint("/password-recovery/{email}", http_method="POST")
        assert res1.is_public
        assert res1.matched_pattern == "/password-recovery/{email}"

        # Express format :param
        res2 = match_intentionally_public_endpoint("/verify-email/:token", http_method="POST")
        assert res2.is_public
        assert res2.matched_pattern == "/verify-email/{token}"

        # Next.js format [param]
        res3 = match_intentionally_public_endpoint("/verify-email/[token]", http_method="POST")
        assert res3.is_public
        assert res3.matched_pattern == "/verify-email/{token}"

    def test_deny_overrides(self):
        # Administrative terms in path segments unconditionally deny public status
        deny_routes = [
            "/admin/reset-password-for-any-user",
            "/admin/export-status-report",
            "/admin/login",
            "/manage/login",
            "/management/status",
            "/internal/health",
            "/root/metrics",
            "/superuser/token",
            "/sudo/login",
            "/impersonate/token",
            "/users/all-users",
            "/users/delete",
            "/api/debug/health",
            "/system/console",
            "/payments/refund",
            "/refund/token",
        ]
        for route in deny_routes:
            res = match_intentionally_public_endpoint(route, http_method="POST")
            assert not res.is_public, f"Route '{route}' should be blocked by deny override"
            assert res.deny_term is not None, f"Expected deny term for '{route}'"

        # Deny terms in handler name also trigger deny override
        res_h = match_intentionally_public_endpoint("/login", handler_name="admin_login_override", http_method="POST")
        assert not res_h.is_public
        assert res_h.deny_term == "admin"

    def test_state_changing_method_restrictions(self):
        # Read method on health is public
        assert is_intentionally_public_endpoint("/health", http_method="GET")

        # Mutating method on health is NOT in allowlist -> NOT public
        assert not is_intentionally_public_endpoint("/health", http_method="POST")
        assert not is_intentionally_public_endpoint("/health", http_method="DELETE")
        assert not is_intentionally_public_endpoint("/status", http_method="PUT")
        assert not is_intentionally_public_endpoint("/metrics", http_method="PATCH")

        # State-changing method on allowlisted route is public
        assert is_intentionally_public_endpoint("/login", http_method="POST")
        assert is_intentionally_public_endpoint("/register", http_method="POST")
        assert is_intentionally_public_endpoint("/token", http_method="POST")

    def test_unanchored_and_arbitrary_tokens_flagged(self):
        # These previously bypassed authentication because tokens appeared in path
        assert not is_intentionally_public_endpoint("/users/{user_id}/token", "get_user_token", http_method="GET")
        assert not is_intentionally_public_endpoint("/api/v1/users/{id}/token", "get_tok", http_method="GET")
        assert not is_intentionally_public_endpoint("/orders/status-check", "status_check", http_method="GET")


class TestPythonFastAPIReproduction:
    """Verifies Python FastAPI reproduction endpoints produce expected findings."""

    def test_reproduction_endpoints_flagged_except_login_and_health(self):
        code = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/admin/reset-password-for-any-user")
def reset_pwd():
    return {"status": "ok"}

@app.get("/users/{user_id}/token")
def get_tok(user_id: int):
    return {"token": "123"}

@app.get("/admin/export-status-report")
def export_rep():
    return {"status": "exported"}

@app.post("/login")
def login():
    return {"token": "abc"}

@app.get("/health")
def health():
    return {"health": "ok"}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py") as f:
            f.write(code)
            f.flush()
            unit = PythonParser().parse_file(Path(f.name), "app.py")
            ctx = PythonASTContext(unit)

            auth_findings = PotentiallyUnprotectedEndpointRule().analyze_file(ctx)
            authz_findings = PotentiallyMissingAuthorizationRule().analyze_file(ctx)

            flagged_routes_auth = {f.metadata.get("route_path") for f in auth_findings}
            flagged_routes_authz = {f.metadata.get("route_path") for f in authz_findings}

            # /login and /health MUST NOT be flagged
            assert "/login" not in flagged_routes_auth
            assert "/health" not in flagged_routes_auth
            assert "/login" not in flagged_routes_authz
            assert "/health" not in flagged_routes_authz

            # The 3 reproduction security bypasses MUST be flagged
            assert "/admin/reset-password-for-any-user" in flagged_routes_auth
            assert "/users/{user_id}/token" in flagged_routes_auth
            assert "/admin/export-status-report" in flagged_routes_auth

            assert "/admin/reset-password-for-any-user" in flagged_routes_authz
            assert "/admin/export-status-report" in flagged_routes_authz

            # Verify explainable audit trail in finding metadata
            admin_finding = next(f for f in auth_findings if f.metadata.get("route_path") == "/admin/reset-password-for-any-user")
            assert "admin" in admin_finding.metadata.get("public_deny_reason", "")

    def test_fastapi_template_routes_stay_public_and_admin_login_flagged(self):
        code = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/login/access-token")
def login_tok():
    return {"token": "abc"}

@app.post("/password-recovery/{email}")
def pwd_rec(email: str):
    return {"msg": "sent"}

@app.post("/reset-password/")
def reset_pwd():
    return {"msg": "reset"}

@app.post("/admin/login")
def admin_login():
    return {"token": "secret"}

@app.get("/api/v1/users/{id}/token")
def user_tok(id: int):
    return {"token": "123"}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py") as f:
            f.write(code)
            f.flush()
            unit = PythonParser().parse_file(Path(f.name), "app.py")
            ctx = PythonASTContext(unit)

            findings = PotentiallyUnprotectedEndpointRule().analyze_file(ctx)
            flagged_routes = {f.metadata.get("route_path") for f in findings}

            # Template public routes stay public
            assert "/login/access-token" not in flagged_routes
            assert "/password-recovery/{email}" not in flagged_routes
            assert "/reset-password/" not in flagged_routes

            # /admin/login is flagged due to deny override
            assert "/admin/login" in flagged_routes

            # /api/v1/users/{id}/token is flagged (not public)
            assert "/api/v1/users/{id}/token" in flagged_routes


class TestJSTSReproduction:
    """Verifies JS/TS Express, Fastify, and NestJS reproduction."""

    def test_express_reproduction(self):
        code = """
const express = require("express");
const app = express();

app.post("/admin/reset-password-for-any-user", (req, res) => res.json({}));
app.get("/users/:user_id/token", (req, res) => res.json({}));
app.get("/admin/export-status-report", (req, res) => res.json({}));
app.post("/login", (req, res) => res.json({}));
app.get("/health", (req, res) => res.json({}));
app.post("/admin/login", (req, res) => res.json({}));
app.get("/api/v1/users/:id/token", (req, res) => res.json({}));
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js") as f:
            f.write(code)
            f.flush()
            unit = JSTSParser().parse_file(Path(f.name), "app.js", SupportedLanguage.JAVASCRIPT)
            ctx = JSTSASTContext(unit)

            auth_findings = JSUnprotectedEndpointRule().analyze(ctx)
            authz_findings = JSMissingAuthorizationRule().analyze(ctx)

            flagged_auth = {f.metadata.get("route_path") for f in auth_findings}
            flagged_authz = {f.metadata.get("route_path") for f in authz_findings}

            assert "/login" not in flagged_auth
            assert "/health" not in flagged_auth

            assert "/admin/reset-password-for-any-user" in flagged_auth
            assert "/users/:user_id/token" in flagged_auth
            assert "/admin/export-status-report" in flagged_auth
            assert "/admin/login" in flagged_auth
            assert "/api/v1/users/:id/token" in flagged_auth

            assert "/admin/reset-password-for-any-user" in flagged_authz
            assert "/admin/export-status-report" in flagged_authz

    def test_fastify_reproduction(self):
        code = """
const fastify = require("fastify")();

fastify.post("/admin/reset-password-for-any-user", async () => ({}));
fastify.get("/users/:user_id/token", async () => ({}));
fastify.get("/admin/export-status-report", async () => ({}));
fastify.post("/login", async () => ({}));
fastify.get("/health", async () => ({}));
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js") as f:
            f.write(code)
            f.flush()
            unit = JSTSParser().parse_file(Path(f.name), "app.js", SupportedLanguage.JAVASCRIPT)
            ctx = JSTSASTContext(unit)

            auth_findings = JSUnprotectedEndpointRule().analyze(ctx)
            flagged_auth = {f.metadata.get("route_path") for f in auth_findings}

            assert "/login" not in flagged_auth
            assert "/health" not in flagged_auth
            assert "/admin/reset-password-for-any-user" in flagged_auth
            assert "/users/:user_id/token" in flagged_auth
            assert "/admin/export-status-report" in flagged_auth

    def test_nestjs_reproduction(self):
        code = """
import { Controller, Get, Post } from "@nestjs/common";

@Controller("admin")
export class AdminController {
    @Post("reset-password-for-any-user")
    resetPwd() { return {}; }

    @Get("export-status-report")
    exportRep() { return {}; }

    @Post("login")
    login() { return {}; }
}

@Controller("users")
export class UsersController {
    @Get(":user_id/token")
    getToken() { return {}; }
}

@Controller()
export class PublicController {
    @Post("login")
    login() { return {}; }

    @Get("health")
    health() { return {}; }
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ts") as f:
            f.write(code)
            f.flush()
            unit = JSTSParser().parse_file(Path(f.name), "app.ts", SupportedLanguage.TYPESCRIPT)
            ctx = JSTSASTContext(unit)

            auth_findings = JSUnprotectedEndpointRule().analyze(ctx)
            flagged = {f.metadata.get("route_path") for f in auth_findings}

            assert "/login" not in flagged
            assert "/health" not in flagged
            assert "/admin/reset-password-for-any-user" in flagged
            assert "/admin/export-status-report" in flagged
            assert "/admin/login" in flagged
            assert "/users/:user_id/token" in flagged


class TestPublicEndpointsSkippedCoverage:
    """Verifies that public endpoints skipped are tracked in scoring coverage."""

    def test_public_endpoints_skipped_counter(self):
        code = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/login")
def login():
    return {"token": "abc"}

@app.get("/health")
def health():
    return {"health": "ok"}

@app.get("/users/{user_id}/token")
def token(user_id: int):
    return {"token": "123"}
"""
        service = ScanService()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text(code)
            scan = service.execute_scan(Path(tmpdir))

            assert scan.score is not None
            assert scan.score.coverage is not None
            # /login and /health are public -> 2 skipped
            assert scan.score.coverage.public_endpoints_skipped == 2
            assert scan.score.coverage.total_routes_detected == 3
