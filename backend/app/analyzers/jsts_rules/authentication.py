"""JavaScript and TypeScript Authentication Consistency static analysis rules.

Implements deterministic AST checks mirroring the Phase 5 Python rules:
- ENT-AUTH-001: Potentially Unprotected Security-Sensitive Endpoint
- ENT-AUTH-002: Inconsistent Authentication Enforcement
- ENT-AUTH-003: Duplicated Local Authentication Logic
"""

from __future__ import annotations

from app.analyzers.jsts_context import JSTSASTContext
from app.analyzers.jsts_rules.detector import JSFrameworkRouteDetector
from app.analyzers.security.models import EndpointDefinition
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.scoring.weights import (
    SENSITIVE_DATA_TERMS,
    SENSITIVE_ROUTE_TERMS,
    drop_severity_one_level,
    is_intentionally_public_endpoint,
)


class JSUnprotectedEndpointRule:
    """ENT-AUTH-001: Potentially Unprotected Security-Sensitive Endpoint in JS/TS."""

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
            "Detects security-sensitive route or endpoint definitions in JavaScript/TypeScript "
            "where no recognizable authentication guard, middleware, or session check is statically present."
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
            "Enforce authentication using framework middleware (e.g. Express auth middleware, "
            "Fastify preHandler guard, or Next.js route protection)."
        )

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description=self.description,
            default_severity=self.default_severity,
            default_confidence=self.default_confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template=self.impact,
            recommendation_template=self.recommendation,
            rationale="Unprotected sensitive endpoints create critical attack surface for unauthorized state alteration.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        endpoints = JSFrameworkRouteDetector.extract_endpoints(context)
        findings: list[Finding] = []

        for ep in endpoints:
            if (
                ep.is_security_sensitive
                and not ep.is_public
                and not is_intentionally_public_endpoint(ep.route_path, ep.symbol)
                and not ep.has_authentication
                and not ep.has_authorization
            ):
                findings.append(self.create_finding(context, ep))

        return findings

    def create_finding(self, context: JSTSASTContext, ep: EndpointDefinition) -> Finding:
        snippet = context.extract_snippet(
            ep.location.line_start,
            ep.location.line_end,
            context_before=1,
            context_after=1,
        )

        reasons_str = ", ".join(ep.sensitivity_reasons) if ep.sensitivity_reasons else "sensitive route"
        desc = (
            f"Endpoint '{ep.display_route}' appears to be security-sensitive ({reasons_str}) "
            f"but no recognizable authentication guard (e.g. middleware, token check, or session check) "
            f"is statically present."
        )

        path_lower = (ep.route_path or "").lower()
        sym_lower = (ep.symbol or "").lower()
        combined = f"{path_lower} {sym_lower}"

        is_sensitive = any(term in combined for term in SENSITIVE_ROUTE_TERMS) or (
            "/admin" in path_lower or "/payment" in path_lower or "/refund" in path_lower
        )
        is_mutating = any(m in ("POST", "PUT", "DELETE", "PATCH") for m in ep.http_methods)

        if is_sensitive and is_mutating:
            severity = Severity.CRITICAL
            conf = Confidence.HIGH
        elif is_sensitive:
            severity = Severity.HIGH
            conf = Confidence.HIGH
        else:
            severity = self.default_severity
            conf = (
                Confidence.HIGH
                if is_mutating and len(ep.sensitivity_reasons) >= 2
                else self.default_confidence
            )

        # If response body shows no sensitive data, drop severity by one level
        has_sensitive_response = any(term in snippet.content.lower() for term in SENSITIVE_DATA_TERMS)
        if not has_sensitive_response:
            severity = drop_severity_one_level(severity)

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
            severity=severity,
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


class JSInconsistentAuthenticationRule:
    """ENT-AUTH-002: Inconsistent Authentication Enforcement in JS/TS."""

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
            "Detects comparable endpoints in a route group where some routes enforce authentication "
            "and others omit it."
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
            "making it difficult to reason about access guarantees and increasing unintentional exposure."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Align security controls across the route group by applying consistent authentication enforcement."
        )

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description=self.description,
            default_severity=self.default_severity,
            default_confidence=self.default_confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template=self.impact,
            recommendation_template=self.recommendation,
            rationale="Inconsistent endpoint protection in the same sub-path indicates incomplete security application.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        endpoints = JSFrameworkRouteDetector.extract_endpoints(context)
        return self.analyze_endpoint_groups(context, endpoints)

    def analyze_endpoint_groups(
        self,
        context: JSTSASTContext,
        endpoints: list[EndpointDefinition],
    ) -> list[Finding]:
        findings: list[Finding] = []
        groups: dict[str, list[EndpointDefinition]] = {}
        for ep in endpoints:
            groups.setdefault(ep.route_group, []).append(ep)

        for group_name, eps in groups.items():
            if len(eps) < 2:
                continue

            auth_eps = [e for e in eps if e.has_authentication]
            unauth_eps = [
                e for e in eps
                if not e.has_authentication
                and not e.is_public
                and not is_intentionally_public_endpoint(e.route_path, e.symbol)
            ]

            if auth_eps and unauth_eps:
                peer_desc = [f"{e.display_route} ({e.auth_evidence[0].guard_name})" for e in auth_eps]

                for ep in unauth_eps:
                    snippet = context.extract_snippet(
                        ep.location.line_start,
                        ep.location.line_end,
                        context_before=1,
                        context_after=1,
                    )
                    desc = (
                        f"Inconsistent authentication in route group '{group_name}': peer endpoints "
                        f"({', '.join(peer_desc)}) enforce authentication, but '{ep.display_route}' "
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

                    path_lower = (ep.route_path or "").lower()
                    is_mutating = any(m in ("POST", "PUT", "DELETE", "PATCH") for m in ep.http_methods)
                    is_sensitive = any(term in path_lower for term in SENSITIVE_ROUTE_TERMS)
                    sev = (
                        Severity.CRITICAL
                        if is_sensitive and is_mutating
                        else (Severity.HIGH if is_sensitive or is_mutating else self.default_severity)
                    )

                    findings.append(
                        Finding(
                            id=fid,
                            category=self.category,
                            rule_id=self.rule_id,
                            severity=sev,
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
                                "unprotected_route": ep.route_path,
                                "protected_peers": [e.route_path for e in auth_eps],
                            },
                        )
                    )

        return findings


class JSDuplicatedAuthenticationRule:
    """ENT-AUTH-003: Duplicated Local Authentication Logic in JS/TS."""

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
            "Detects repeated ad-hoc authentication logic implemented inline across multiple endpoints "
            "instead of using centralized framework middleware."
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
            "Duplicated authentication checks increase maintenance overhead and the risk that a bug "
            "or vulnerability fix applied to one check will not be applied to all copies."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Extract repeated local authentication checks into reusable middleware or guard functions."
        )

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description=self.description,
            default_severity=self.default_severity,
            default_confidence=self.default_confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template=self.impact,
            recommendation_template=self.recommendation,
            rationale="Local authentication logic duplicated across handlers leads to security rot.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        endpoints = JSFrameworkRouteDetector.extract_endpoints(context)
        return self.analyze_endpoints_for_duplication(context, endpoints)

    def analyze_endpoints_for_duplication(
        self,
        context: JSTSASTContext,
        endpoints: list[EndpointDefinition],
    ) -> list[Finding]:
        findings: list[Finding] = []
        inline_eps = [
            e
            for e in endpoints
            if any(ev.evidence_kind == "inline_auth_check" for ev in e.auth_evidence)
        ]

        if len(inline_eps) >= 2:
            first_ep = inline_eps[0]
            snippet = context.extract_snippet(
                first_ep.location.line_start,
                first_ep.location.line_end,
                context_before=1,
                context_after=1,
            )
            peer_routes = [e.display_route for e in inline_eps]
            desc = (
                f"Repeated inline authentication checks detected across {len(inline_eps)} endpoints: "
                f"({', '.join(peer_routes)}). Authentication logic should be factored into reusable middleware."
            )
            sig = f"{context.file_path}:duplicated_inline_auth"
            fid = Finding.generate_deterministic_id(
                rule_id=self.rule_id,
                file=context.file_path,
                line_start=first_ep.location.line_start,
                line_end=first_ep.location.line_end,
                symbol=first_ep.symbol,
                evidence_signature=sig,
            )

            findings.append(
                Finding(
                    id=fid,
                    category=self.category,
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    confidence=self.default_confidence,
                    file=context.file_path,
                    line_start=first_ep.location.line_start,
                    line_end=first_ep.location.line_end,
                    column_start=first_ep.location.col_offset,
                    column_end=first_ep.location.end_col_offset,
                    symbol=first_ep.symbol,
                    title=self.name,
                    description=desc,
                    evidence=snippet,
                    impact=self.impact,
                    recommendation=self.recommendation,
                    fingerprint=Finding.generate_fingerprint(
                        rule_id=self.rule_id,
                        file=context.file_path,
                        symbol=first_ep.symbol,
                        pattern_signature=sig,
                    ),
                    metadata={"endpoints": peer_routes},
                )
            )

        return findings
