"""Phase 3 Regression Tests: Express middleware ordering, mount-path scoping, and pass-through inspection.

Tests:
1. No-op middleware flags ENT-AUTH-001.
2. Late app.use flags the three early routes.
3. Mounted-path case protects only sub-routes.
4. Real jwt.verify control stays free of ENT-AUTH-001 but keeps ENT-AUTHZ-001 on admin routes.
5. Imported middleware gives MEDIUM-confidence evidence.
"""

import tempfile
from pathlib import Path

from app.analyzers.jsts_context import JSTSASTContext
from app.analyzers.jsts_rules.authentication import JSUnprotectedEndpointRule
from app.analyzers.jsts_rules.authorization import JSMissingAuthorizationRule
from app.analyzers.jsts_rules.detector import JSFrameworkRouteDetector
from app.models.domain.enums import Confidence, SupportedLanguage
from app.parser.jsts.parser import JSTSParser


def _parse_source(code: str, filename: str = "app.js") -> JSTSASTContext:
    parser = JSTSParser()
    with tempfile.NamedTemporaryFile(suffix=f"_{filename}", mode="w", delete=False) as f:
        f.write(code)
        f.flush()
        path = Path(f.name)

    try:
        lang = SupportedLanguage.TYPESCRIPT if filename.endswith((".ts", ".tsx")) else SupportedLanguage.JAVASCRIPT
        unit = parser.parse_file(path, filename, lang)
        return JSTSASTContext(unit)
    finally:
        path.unlink(missing_ok=True)


def test_noop_middleware_flags_auth001():
    """Problem 1: const auth = (req,res,next) => next(); must not count as auth evidence."""
    code = """
    const express = require('express');
    const app = express();

    const auth = (req, res, next) => next();

    app.post('/admin/delete-user', auth, (req, res) => {
        res.send('ok');
    });
    """
    ctx = _parse_source(code)
    auth_rule = JSUnprotectedEndpointRule()
    findings = auth_rule.analyze(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "ENT-AUTH-001"
    assert "/admin/delete-user" in findings[0].description


def test_noop_function_statement_flags_auth001():
    """No-op middleware declared as a standard function statement must also not count."""
    code = """
    const express = require('express');
    const app = express();

    function authenticate(req, res, next) {
        return next();
    }

    app.post('/admin/delete-user', authenticate, handler);
    """
    ctx = _parse_source(code)
    auth_rule = JSUnprotectedEndpointRule()
    findings = auth_rule.analyze(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "ENT-AUTH-001"


def test_late_app_use_flags_early_routes():
    """Problem 2: routes registered BEFORE app.use(requireAuth) are not protected."""
    code = """
    const express = require('express');
    const app = express();

    app.post('/admin/delete-user', handleDeleteUser);
    app.get('/admin/export', handleExport);
    app.post('/payments/refund', handleRefund);

    app.use(requireAuth);

    app.get('/admin/status', handleStatus);
    """
    ctx = _parse_source(code)
    auth_rule = JSUnprotectedEndpointRule()
    findings = auth_rule.analyze(ctx)

    flagged_lines = [f.line_start for f in findings if f.rule_id == "ENT-AUTH-001"]
    # All 3 early routes must be flagged
    assert len(flagged_lines) >= 3
    # Check endpoints
    flagged_endpoints = [f.description for f in findings]
    assert any("/admin/delete-user" in d for d in flagged_endpoints)
    assert any("/admin/export" in d for d in flagged_endpoints)
    assert any("/payments/refund" in d for d in flagged_endpoints)


def test_mounted_path_scoping():
    """app.use('/api', requireAuth) protects only routes matching or nested under /api."""
    code = """
    const express = require('express');
    const app = express();

    app.use('/api', requireAuth);

    app.post('/api/users/create', handleCreate);
    app.post('/admin/export', handleExport);
    """
    ctx = _parse_source(code)
    auth_rule = JSUnprotectedEndpointRule()
    findings = auth_rule.analyze(ctx)

    # Only /admin/export should be flagged; /api/users/create is protected by mounted middleware
    flagged = [f for f in findings if f.rule_id == "ENT-AUTH-001"]
    assert len(flagged) == 1
    assert "/admin/export" in flagged[0].description
    assert "/api/users/create" not in flagged[0].description


def test_real_jwt_verify_middleware_stays_free_of_auth001_but_flags_authz001():
    """Real jwt.verify middleware before routes clears ENT-AUTH-001, but admin routes keep ENT-AUTHZ-001."""
    code = """
    const express = require('express');
    const app = express();

    const requireAuth = (req, res, next) => {
        const token = req.headers['authorization'];
        if (!token) return res.status(401).send();
        jwt.verify(token, 'secret');
        next();
    };

    app.use(requireAuth);

    app.post('/admin/delete-user', handleDelete);
    app.get('/admin/export', handleExport);
    app.post('/payments/refund', handleRefund);
    """
    ctx = _parse_source(code)
    auth_rule = JSUnprotectedEndpointRule()
    authz_rule = JSMissingAuthorizationRule()

    auth_findings = auth_rule.analyze(ctx)
    authz_findings = authz_rule.analyze(ctx)

    # No authentication missing findings
    assert len(auth_findings) == 0

    # Administrative and sensitive endpoints still flag missing authorization checks
    assert len(authz_findings) == 3
    assert all(f.rule_id == "ENT-AUTHZ-001" for f in authz_findings)


def test_imported_middleware_gives_medium_confidence():
    """Unresolved or imported middleware name evidence must be MEDIUM confidence, never HIGH."""
    code = """
    import express from 'express';
    import { requireAuth } from './middleware/auth';

    const app = express();
    app.use(requireAuth);

    app.post('/api/users/create', handleCreate);
    """
    ctx = _parse_source(code)
    endpoints = JSFrameworkRouteDetector.extract_endpoints(ctx)

    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.has_authentication is True

    # Check evidence confidence
    auth_ev = ep.auth_evidence
    assert len(auth_ev) >= 1
    assert any(ev.confidence == Confidence.MEDIUM for ev in auth_ev)
    assert not any(ev.confidence == Confidence.HIGH for ev in auth_ev)
    assert any("lowered to MEDIUM" in ev.details for ev in auth_ev)
