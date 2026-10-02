"""Rule definitions and implementations for Authentication & Authorization Debt Analyzers."""

from __future__ import annotations

import ast

from app.analyzers.context import PythonASTContext
from app.analyzers.rules.base import BaseRule
from app.analyzers.security.frameworks import FrameworkRouteDetector
from app.analyzers.security.models import (
    EndpointDefinition,
)
from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import Finding

# =============================================================================
# Authentication Rules (ENT-AUTH-001, ENT-AUTH-002, ENT-AUTH-003)
# =============================================================================


class PotentiallyUnprotectedEndpointRule(BaseRule):
    """ENT-AUTH-001: Potentially Unprotected Security-Sensitive Endpoint."""

    @property
    def rule_id(self) -> str:
        return "ENT-AUTH-001"

    @property
    def name(self) -> str:
        return "Potentially Unprotected Security-Sensitive Endpoint"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHENTICATION_CONSISTENCY

    @property
    def description(self) -> str:
        return (
            "Detects security-sensitive route or endpoint definitions where no recognizable "
            "authentication guard, dependency, or decorator is statically present."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.MEDIUM

    @property
    def impact(self) -> str:
        return (
            "Unprotected endpoints that modify state or access sensitive resources risk "
            "unauthorized access and data tampering if authentication was omitted unintentionally."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Enforce authentication using a framework-approved guard (e.g. FastAPI "
            "Depends(get_current_user), Flask @login_required, or Django @login_required)."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        findings: list[Finding] = []

        for ep in endpoints:
            if (
                ep.is_security_sensitive
                and not ep.is_public
                and not ep.has_authentication
                and not ep.has_authorization
            ):
                finding = self.create_finding(context, ep)
                findings.append(finding)

        return findings

    def create_finding(self, context: PythonASTContext, ep: EndpointDefinition) -> Finding:
        snippet = context.extract_snippet(
            ep.location.line_start,
            ep.location.line_end,
            context_before=1,
            context_after=1,
        )

        reasons_str = ", ".join(ep.sensitivity_reasons) if ep.sensitivity_reasons else "sensitive route"
        desc = (
            f"Endpoint '{ep.display_route}' appears to be security-sensitive ({reasons_str}) "
            f"but no recognizable authentication guard (e.g. Depends, decorator, or session check) "
            f"is statically present."
        )

        # High confidence if mutating method AND sensitive keyword
        conf = (
            Confidence.HIGH
            if any(m in ("POST", "PUT", "DELETE", "PATCH") for m in ep.http_methods)
            and len(ep.sensitivity_reasons) >= 2
            else self.default_confidence
        )

        sig = f"{ep.file_path}:{ep.symbol}:{ep.display_route}:unprotected"
        fid = Finding.generate_deterministic_id(
            rule_id=self.rule_id,
            file=ep.file_path,
            line_start=ep.location.line_start,
            line_end=ep.location.line_end,
            symbol=ep.symbol,
            evidence_signature=sig,
        )

        return Finding(
            id=fid,
            category=self.category,
            rule_id=self.rule_id,
            severity=self.default_severity,
            confidence=conf,
            file=ep.file_path,
            line_start=ep.location.line_start,
            line_end=ep.location.line_end,
            column_start=ep.location.col_offset,
            column_end=ep.location.end_col_offset,
            symbol=ep.symbol,
            title=self.name,
            description=desc,
            evidence=snippet,
            impact=self.impact,
            recommendation=self.recommendation,
            fingerprint=Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=ep.file_path,
                symbol=ep.symbol,
                pattern_signature=sig,
            ),
            metadata={
                "http_methods": ep.http_methods,
                "route_path": ep.route_path,
                "framework": ep.framework.value,
                "sensitivity_reasons": ep.sensitivity_reasons,
                "route_group": ep.route_group,
            },
        )


class InconsistentAuthenticationRule(BaseRule):
    """ENT-AUTH-002: Inconsistent Authentication Enforcement."""

    @property
    def rule_id(self) -> str:
        return "ENT-AUTH-002"

    @property
    def name(self) -> str:
        return "Inconsistent Authentication Enforcement"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHENTICATION_CONSISTENCY

    @property
    def description(self) -> str:
        return (
            "Detects comparable endpoints in a route group where some routes use a recognizable "
            "authentication mechanism and others do not."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Inconsistent security controls across related routes create architectural debt, "
            "making it difficult to reason about access guarantees and increasing the likelihood of unintentional exposure."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Align security controls across the route group by applying consistent authentication enforcement."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        return self.analyze_endpoint_groups(context, endpoints)

    def analyze_endpoint_groups(
        self,
        context: PythonASTContext,
        endpoints: list[EndpointDefinition],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Group endpoints by route_group
        groups: dict[str, list[EndpointDefinition]] = {}
        for ep in endpoints:
            groups.setdefault(ep.route_group, []).append(ep)

        for group_name, eps in groups.items():
            if len(eps) < 2:
                continue

            auth_eps = [e for e in eps if e.has_authentication]
            unauth_eps = [e for e in eps if not e.has_authentication and not e.is_public]

            # Inconsistency: group has authenticated routes, but some non-public routes lack auth
            if auth_eps and unauth_eps:
                peer_descriptions = [f"{e.display_route} ({e.auth_evidence[0].guard_name})" for e in auth_eps]

                for ep in unauth_eps:
                    snippet = context.extract_snippet(
                        ep.location.line_start,
                        ep.location.line_end,
                        context_before=1,
                        context_after=1,
                    )

                    desc = (
                        f"Inconsistent authentication in route group '{group_name}': peer endpoints "
                        f"({', '.join(peer_descriptions)}) enforce authentication, but '{ep.display_route}' "
                        f"omits authentication enforcement."
                    )

                    sig = f"{ep.file_path}:{ep.symbol}:{group_name}:inconsistent_auth"
                    fid = Finding.generate_deterministic_id(
                        rule_id=self.rule_id,
                        file=ep.file_path,
                        line_start=ep.location.line_start,
                        line_end=ep.location.line_end,
                        symbol=ep.symbol,
                        evidence_signature=sig,
                    )

                    findings.append(
                        Finding(
                            id=fid,
                            category=self.category,
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            confidence=self.default_confidence,
                            file=ep.file_path,
                            line_start=ep.location.line_start,
                            line_end=ep.location.line_end,
                            column_start=ep.location.col_offset,
                            column_end=ep.location.end_col_offset,
                            symbol=ep.symbol,
                            title=self.name,
                            description=desc,
                            evidence=snippet,
                            impact=self.impact,
                            recommendation=self.recommendation,
                            fingerprint=Finding.generate_fingerprint(
                                rule_id=self.rule_id,
                                file=ep.file_path,
                                symbol=ep.symbol,
                                pattern_signature=sig,
                            ),
                            metadata={
                                "route_group": group_name,
                                "inconsistent_endpoint": ep.display_route,
                                "authenticated_peers": [e.display_route for e in auth_eps],
                            },
                        )
                    )

        return findings


class DuplicatedAuthenticationRule(BaseRule):
    """ENT-AUTH-003: Duplicated Local Authentication Logic."""

    @property
    def rule_id(self) -> str:
        return "ENT-AUTH-003"

    @property
    def name(self) -> str:
        return "Duplicated Local Authentication Logic"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHENTICATION_CONSISTENCY

    @property
    def description(self) -> str:
        return (
            "Detects repeated authentication logic implemented independently across multiple "
            "endpoints instead of using a shared dependency, decorator, or middleware guard."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.LOW

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Duplicating authentication logic across handlers increases maintenance burden "
            "and risks subtle discrepancies in token validation or credential checks."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Consolidate local authentication logic into a shared middleware, decorator, "
            "or dependency guard."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        return self.analyze_endpoints_for_duplication(context, endpoints)

    def analyze_endpoints_for_duplication(
        self,
        context: PythonASTContext,
        endpoints: list[EndpointDefinition],
    ) -> list[Finding]:
        if not context.ast_root:
            return []

        # Find inline patterns across endpoints
        endpoint_patterns: list[tuple[EndpointDefinition, str, int, str]] = []

        ast_func_map: dict[tuple[str, int], ast.AST] = {}
        for node in ast.walk(context.ast_root):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ast_func_map[(node.name, getattr(node, "lineno", 0))] = node

        for ep in endpoints:
            func_node = ast_func_map.get((ep.symbol.split(".")[-1], ep.location.line_start))
            if not func_node:
                continue

            for node in ast.walk(func_node):
                # Pattern 1: Manual Header lookup: request.headers.get("Authorization") or headers["Authorization"]
                if isinstance(node, ast.Call):
                    call_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    if any(
                        term in call_str
                        for term in (
                            'headers.get("Authorization"',
                            "headers.get('Authorization'",
                            'headers.get("authorization"',
                            "headers.get('authorization'",
                            'headers.get("X-API-Key"',
                            "headers.get('X-API-Key'",
                        )
                    ):
                        endpoint_patterns.append((ep, "header_extraction", getattr(node, "lineno", ep.location.line_start), call_str))
                    elif "jwt.decode(" in call_str:
                        endpoint_patterns.append((ep, "inline_jwt_decode", getattr(node, "lineno", ep.location.line_start), call_str))
                    elif any(term in call_str for term in ('session.get("user_id"', "session.get('user_id'", 'session.get("user"', "session.get('user'")):
                        endpoint_patterns.append((ep, "session_user_lookup", getattr(node, "lineno", ep.location.line_start), call_str))
                elif isinstance(node, ast.Subscript):
                    sub_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    if any(
                        term in sub_str
                        for term in (
                            'headers["Authorization"]',
                            "headers['Authorization']",
                            'headers["authorization"]',
                            "headers['authorization']",
                        )
                    ):
                        endpoint_patterns.append((ep, "header_extraction", getattr(node, "lineno", ep.location.line_start), sub_str))

        # Check if patterns occur across 2 or more endpoints
        pattern_groups: dict[str, list[tuple[EndpointDefinition, str, int, str]]] = {}
        for item in endpoint_patterns:
            pattern_groups.setdefault(item[1], []).append(item)

        findings: list[Finding] = []
        for _pat_kind, items in pattern_groups.items():
            # Must appear in at least 2 distinct endpoints to be considered duplicated debt
            distinct_eps = {it[0].symbol for it in items}
            if len(distinct_eps) >= 2:
                for ep, pkind, lineno, expr in items:
                    snippet = context.extract_snippet(
                        lineno,
                        lineno,
                        context_before=1,
                        context_after=1,
                    )
                    other_symbols = [s for s in distinct_eps if s != ep.symbol]

                    desc = (
                        f"Endpoint '{ep.display_route}' contains inline authentication logic "
                        f"(`{expr}`) duplicated across multiple handlers ({', '.join(other_symbols)}). "
                        f"Local authentication logic should be centralized into a shared guard or dependency."
                    )

                    sig = f"{ep.file_path}:{ep.symbol}:{pkind}:{lineno}"
                    fid = Finding.generate_deterministic_id(
                        rule_id=self.rule_id,
                        file=ep.file_path,
                        line_start=lineno,
                        line_end=lineno,
                        symbol=ep.symbol,
                        evidence_signature=sig,
                    )

                    findings.append(
                        Finding(
                            id=fid,
                            category=self.category,
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            confidence=self.default_confidence,
                            file=ep.file_path,
                            line_start=lineno,
                            line_end=lineno,
                            symbol=ep.symbol,
                            title=self.name,
                            description=desc,
                            evidence=snippet,
                            impact=self.impact,
                            recommendation=self.recommendation,
                            fingerprint=Finding.generate_fingerprint(
                                rule_id=self.rule_id,
                                file=ep.file_path,
                                symbol=ep.symbol,
                                pattern_signature=sig,
                            ),
                            metadata={
                                "duplicated_pattern": pkind,
                                "matched_expression": expr,
                                "affected_peers": other_symbols,
                            },
                        )
                    )

        return findings


# =============================================================================
# Authorization Rules (ENT-AUTHZ-001, ENT-AUTHZ-002, ENT-AUTHZ-003)
# =============================================================================


class PotentiallyMissingAuthorizationRule(BaseRule):
    """ENT-AUTHZ-001: Potentially Missing Authorization Check."""

    @property
    def rule_id(self) -> str:
        return "ENT-AUTHZ-001"

    @property
    def name(self) -> str:
        return "Potentially Missing Authorization Check"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHORIZATION_CONSISTENCY

    @property
    def description(self) -> str:
        return (
            "Detects security-sensitive endpoints that appear to require access control "
            "but contain no recognizable authorization evidence (role, permission, or ownership check)."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.MEDIUM

    @property
    def impact(self) -> str:
        return (
            "Missing authorization checks on privileged routes risk broken access control "
            "(e.g. IDOR, horizontal/vertical privilege escalation) where any authenticated user "
            "can perform administrative or restricted actions."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Enforce role-based access control (RBAC), permission checks, or resource ownership "
            "verification before executing privileged actions."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        findings: list[Finding] = []

        for ep in endpoints:
            # Privileged endpoint check
            if self._requires_access_control(ep) and not ep.has_authorization:
                finding = self.create_finding(context, ep)
                findings.append(finding)

        return findings

    @classmethod
    def _requires_access_control(cls, ep: EndpointDefinition) -> bool:
        """Evaluate if an endpoint represents a privileged / administrative domain."""
        if ep.is_public:
            return False

        path_lower = (ep.route_path or "").lower()
        sym_lower = ep.symbol.lower()

        # Administrative / Privileged path indicators
        is_admin_path = any(
            seg in path_lower
            for seg in ("/admin", "/manage", "/roles", "/permissions", "/privileges", "/system")
        )
        is_admin_sym = any(
            term in sym_lower
            for term in ("admin", "delete_user", "assign_role", "revoke_role", "purge_data", "system_config")
        )

        return is_admin_path or is_admin_sym

    def create_finding(self, context: PythonASTContext, ep: EndpointDefinition) -> Finding:
        snippet = context.extract_snippet(
            ep.location.line_start,
            ep.location.line_end,
            context_before=1,
            context_after=1,
        )

        # High severity for admin routes
        path_lower = (ep.route_path or "").lower()
        is_admin = "/admin" in path_lower or "admin" in ep.symbol.lower()
        severity = Severity.HIGH if is_admin else self.default_severity
        confidence = Confidence.HIGH if is_admin else self.default_confidence

        desc = (
            f"Privileged endpoint '{ep.display_route}' contains no recognizable authorization "
            f"evidence (e.g. role check, permission check, or ownership validation). "
            f"Authentication alone does not ensure the caller has authorization for this resource."
        )

        sig = f"{ep.file_path}:{ep.symbol}:{ep.display_route}:missing_authz"
        fid = Finding.generate_deterministic_id(
            rule_id=self.rule_id,
            file=ep.file_path,
            line_start=ep.location.line_start,
            line_end=ep.location.line_end,
            symbol=ep.symbol,
            evidence_signature=sig,
        )

        return Finding(
            id=fid,
            category=self.category,
            rule_id=self.rule_id,
            severity=severity,
            confidence=confidence,
            file=ep.file_path,
            line_start=ep.location.line_start,
            line_end=ep.location.line_end,
            column_start=ep.location.col_offset,
            column_end=ep.location.end_col_offset,
            symbol=ep.symbol,
            title=self.name,
            description=desc,
            evidence=snippet,
            impact=self.impact,
            recommendation=self.recommendation,
            fingerprint=Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=ep.file_path,
                symbol=ep.symbol,
                pattern_signature=sig,
            ),
            metadata={
                "route_path": ep.route_path,
                "http_methods": ep.http_methods,
                "has_authentication": ep.has_authentication,
            },
        )


class InconsistentAuthorizationRule(BaseRule):
    """ENT-AUTHZ-002: Inconsistent Authorization Enforcement."""

    @property
    def rule_id(self) -> str:
        return "ENT-AUTHZ-002"

    @property
    def name(self) -> str:
        return "Inconsistent Authorization Enforcement"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHORIZATION_CONSISTENCY

    @property
    def description(self) -> str:
        return (
            "Detects structurally related endpoints where some routes enforce authorization "
            "checks and others omit them."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Inconsistent authorization enforcement across related endpoints creates blind spots "
            "where some operations are guarded while others leave access unrestricted."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Harmonize authorization controls across the route group by enforcing consistent "
            "role or permission checks."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        return self.analyze_endpoint_groups(context, endpoints)

    def analyze_endpoint_groups(
        self,
        context: PythonASTContext,
        endpoints: list[EndpointDefinition],
    ) -> list[Finding]:
        findings: list[Finding] = []

        groups: dict[str, list[EndpointDefinition]] = {}
        for ep in endpoints:
            groups.setdefault(ep.route_group, []).append(ep)

        for group_name, eps in groups.items():
            if len(eps) < 2:
                continue

            authz_eps = [e for e in eps if e.has_authorization]
            unauthz_eps = [e for e in eps if not e.has_authorization and not e.is_public]

            # Inconsistency: some endpoints in group enforce authorization, others omit it
            if authz_eps and unauthz_eps:
                peer_descriptions = [f"{e.display_route} ({e.authz_evidence[0].evidence_kind})" for e in authz_eps]

                for ep in unauthz_eps:
                    snippet = context.extract_snippet(
                        ep.location.line_start,
                        ep.location.line_end,
                        context_before=1,
                        context_after=1,
                    )

                    desc = (
                        f"Inconsistent authorization in route group '{group_name}': peer endpoints "
                        f"({', '.join(peer_descriptions)}) enforce authorization checks, whereas "
                        f"'{ep.display_route}' omits authorization verification."
                    )

                    sig = f"{ep.file_path}:{ep.symbol}:{group_name}:inconsistent_authz"
                    fid = Finding.generate_deterministic_id(
                        rule_id=self.rule_id,
                        file=ep.file_path,
                        line_start=ep.location.line_start,
                        line_end=ep.location.line_end,
                        symbol=ep.symbol,
                        evidence_signature=sig,
                    )

                    findings.append(
                        Finding(
                            id=fid,
                            category=self.category,
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            confidence=self.default_confidence,
                            file=ep.file_path,
                            line_start=ep.location.line_start,
                            line_end=ep.location.line_end,
                            column_start=ep.location.col_offset,
                            column_end=ep.location.end_col_offset,
                            symbol=ep.symbol,
                            title=self.name,
                            description=desc,
                            evidence=snippet,
                            impact=self.impact,
                            recommendation=self.recommendation,
                            fingerprint=Finding.generate_fingerprint(
                                rule_id=self.rule_id,
                                file=ep.file_path,
                                symbol=ep.symbol,
                                pattern_signature=sig,
                            ),
                            metadata={
                                "route_group": group_name,
                                "inconsistent_endpoint": ep.display_route,
                                "authorized_peers": [e.display_route for e in authz_eps],
                            },
                        )
                    )

        return findings


class DuplicatedAuthorizationRule(BaseRule):
    """ENT-AUTHZ-003: Duplicated Authorization Logic."""

    @property
    def rule_id(self) -> str:
        return "ENT-AUTHZ-003"

    @property
    def name(self) -> str:
        return "Duplicated Authorization Logic"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHORIZATION_CONSISTENCY

    @property
    def description(self) -> str:
        return (
            "Detects repeated local authorization patterns (e.g. inline role checks) "
            "implemented independently across multiple endpoints instead of using a shared guard or decorator."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.LOW

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Duplicated authorization checks lead to maintenance debt and the potential for "
            "inconsistent permission enforcement when access policies evolve."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Extract repeated authorization checks into a reusable decorator (e.g. @require_role('admin')) "
            "or dependency guard."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        return self.analyze_endpoints_for_duplication(context, endpoints)

    def analyze_endpoints_for_duplication(
        self,
        context: PythonASTContext,
        endpoints: list[EndpointDefinition],
    ) -> list[Finding]:
        if not context.ast_root:
            return []

        endpoint_patterns: list[tuple[EndpointDefinition, str, int, str]] = []

        ast_func_map: dict[tuple[str, int], ast.AST] = {}
        for node in ast.walk(context.ast_root):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ast_func_map[(node.name, getattr(node, "lineno", 0))] = node

        for ep in endpoints:
            func_node = ast_func_map.get((ep.symbol.split(".")[-1], ep.location.line_start))
            if not func_node:
                continue

            for node in ast.walk(func_node):
                if isinstance(node, ast.If):
                    test_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                    test_clean = test_str.replace(" ", "")

                    if any(
                        term in test_clean
                        for term in (
                            'role!="admin"',
                            "role!='admin'",
                            'role=="admin"',
                            "role=='admin'",
                            "notuser.is_superuser",
                            "notcurrent_user.is_admin",
                            "notuser.is_admin",
                            "notuser.is_staff",
                        )
                    ):
                        endpoint_patterns.append((ep, test_clean, getattr(node, "lineno", ep.location.line_start), test_str))

        pattern_groups: dict[str, list[tuple[EndpointDefinition, str, int, str]]] = {}
        for item in endpoint_patterns:
            pattern_groups.setdefault(item[1], []).append(item)

        findings: list[Finding] = []
        for _pat_clean, items in pattern_groups.items():
            distinct_eps = {it[0].symbol for it in items}
            if len(distinct_eps) >= 2:
                for ep, pclean, lineno, expr in items:
                    snippet = context.extract_snippet(
                        lineno,
                        lineno,
                        context_before=1,
                        context_after=1,
                    )
                    other_symbols = [s for s in distinct_eps if s != ep.symbol]

                    desc = (
                        f"Endpoint '{ep.display_route}' contains inline authorization logic "
                        f"(`{expr}`) duplicated across multiple handlers ({', '.join(other_symbols)}). "
                        f"Access control logic should be factored into a reusable decorator or policy guard."
                    )

                    sig = f"{ep.file_path}:{ep.symbol}:{pclean}:{lineno}"
                    fid = Finding.generate_deterministic_id(
                        rule_id=self.rule_id,
                        file=ep.file_path,
                        line_start=lineno,
                        line_end=lineno,
                        symbol=ep.symbol,
                        evidence_signature=sig,
                    )

                    findings.append(
                        Finding(
                            id=fid,
                            category=self.category,
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            confidence=self.default_confidence,
                            file=ep.file_path,
                            line_start=lineno,
                            line_end=lineno,
                            symbol=ep.symbol,
                            title=self.name,
                            description=desc,
                            evidence=snippet,
                            impact=self.impact,
                            recommendation=self.recommendation,
                            fingerprint=Finding.generate_fingerprint(
                                rule_id=self.rule_id,
                                file=ep.file_path,
                                symbol=ep.symbol,
                                pattern_signature=sig,
                            ),
                            metadata={
                                "duplicated_pattern": pclean,
                                "matched_condition": expr,
                                "affected_peers": other_symbols,
                            },
                        )
                    )

        return findings
