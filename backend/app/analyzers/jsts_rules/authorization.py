"""JavaScript and TypeScript Authorization Consistency static analysis rules.

Implements deterministic AST checks mirroring the Phase 5 Python rules:
- ENT-AUTHZ-001: Potentially Missing Authorization Check
- ENT-AUTHZ-002: Inconsistent Authorization Enforcement
- ENT-AUTHZ-003: Duplicated Authorization Logic
"""

from __future__ import annotations

from app.analyzers.jsts_context import JSTSASTContext
from app.analyzers.jsts_rules.detector import JSFrameworkRouteDetector
from app.analyzers.security.models import EndpointDefinition
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.scoring.weights import SENSITIVE_ROUTE_TERMS, is_intentionally_public_endpoint


class JSMissingAuthorizationRule:
    """ENT-AUTHZ-001: Potentially Missing Authorization Check in JS/TS."""

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
            "Detects privileged endpoints in JavaScript/TypeScript (e.g. administrative routes, "
            "role management, payment mutations) where no recognizable authorization check "
            "or role guard is statically present."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.MEDIUM

    @property
    def impact(self) -> str:
        return (
            "Missing authorization checks on privileged routes risk broken access control "
            "(e.g. IDOR, horizontal/vertical privilege escalation) where any authenticated caller "
            "can perform administrative or restricted actions."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Enforce role-based access control (RBAC), permission checks, or ownership verification "
            "before executing privileged operations."
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
            rationale="Unprotected administrative endpoints expose critical functionality to authorization bypass.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        endpoints = JSFrameworkRouteDetector.extract_endpoints(context)
        findings: list[Finding] = []

        for ep in endpoints:
            if self._requires_access_control(ep) and not ep.has_authorization:
                findings.append(self.create_finding(context, ep))

        return findings

    @classmethod
    def _requires_access_control(cls, ep: EndpointDefinition) -> bool:
        if ep.is_public or is_intentionally_public_endpoint(ep.route_path, ep.symbol):
            return False

        path_lower = (ep.route_path or "").lower()
        sym_lower = ep.symbol.lower()

        is_admin = any(
            seg in path_lower
            for seg in ("/admin", "/manage", "/roles", "/permissions", "/privileges", "/system")
        ) or any(
            term in sym_lower
            for term in ("admin", "delete_user", "assign_role", "revoke_role", "purge_data", "system_config")
        )

        is_payment_mutation = (
            any(seg in path_lower for seg in ("/payment", "/refund", "/billing"))
            and any(m in ("POST", "PUT", "DELETE", "PATCH") for m in ep.http_methods)
        )

        is_sensitive_delete = (
            any(m == "DELETE" for m in ep.http_methods)
            and (
                any(seg in path_lower for seg in ("/users/", "/accounts/", "/system/", "/purge"))
                or any(term in sym_lower for term in ("delete_user", "purge_data", "delete_account"))
            )
        )

        return is_admin or is_payment_mutation or is_sensitive_delete

    def create_finding(self, context: JSTSASTContext, ep: EndpointDefinition) -> Finding:
        snippet = context.extract_snippet(
            ep.location.line_start,
            ep.location.line_end,
            context_before=1,
            context_after=1,
        )

        path_lower = (ep.route_path or "").lower()
        sym_lower = (ep.symbol or "").lower()
        combined = f"{path_lower} {sym_lower}"

        is_sensitive = any(term in combined for term in SENSITIVE_ROUTE_TERMS) or (
            "/admin" in path_lower or "admin" in sym_lower or "/refund" in path_lower
        )
        is_mutating = any(m in ("POST", "PUT", "DELETE", "PATCH") for m in ep.http_methods)

        if is_sensitive and is_mutating:
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        elif is_sensitive:
            severity = Severity.HIGH
            confidence = Confidence.HIGH
        else:
            severity = self.default_severity
            confidence = self.default_confidence

        desc = (
            f"Privileged endpoint '{ep.display_route}' contains no recognizable authorization "
            f"evidence (e.g. role guard, permission check, or ownership validation). "
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


class JSInconsistentAuthorizationRule:
    """ENT-AUTHZ-002: Inconsistent Authorization Enforcement in JS/TS."""

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
            "Inconsistent authorization enforcement inside a privileged route group invites "
            "privilege escalation if developers assume the group is uniformly protected."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Apply consistent role or permission guards across all endpoints in the route group."
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
            rationale="Discrepancies in access control within the same domain route group suggest oversight.",
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

            authz_eps = [e for e in eps if e.has_authorization]
            unauthz_eps = [
                e
                for e in eps
                if not e.has_authorization
                and not e.is_public
                and JSMissingAuthorizationRule._requires_access_control(e)
            ]

            if authz_eps and unauthz_eps:
                peer_desc = [f"{e.display_route} ({e.authz_evidence[0].role_or_permission})" for e in authz_eps]

                for ep in unauthz_eps:
                    snippet = context.extract_snippet(
                        ep.location.line_start,
                        ep.location.line_end,
                        context_before=1,
                        context_after=1,
                    )
                    desc = (
                        f"Inconsistent authorization in route group '{group_name}': peer endpoints "
                        f"({', '.join(peer_desc)}) enforce authorization, but '{ep.display_route}' "
                        f"omits access control checks."
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

                    path_lower = (ep.route_path or "").lower()
                    is_mutating = any(m in ("POST", "PUT", "DELETE", "PATCH") for m in ep.http_methods)
                    is_sensitive = any(term in path_lower for term in SENSITIVE_ROUTE_TERMS) or "/admin" in path_lower
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
                                "unauthorized_route": ep.route_path,
                                "authorized_peers": [e.route_path for e in authz_eps],
                            },
                        )
                    )

        return findings


class JSDuplicatedAuthorizationRule:
    """ENT-AUTHZ-003: Duplicated Authorization Logic in JS/TS."""

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
            "Detects repeated ad-hoc role or permission checks implemented inline across multiple endpoints "
            "instead of using reusable authorization middleware."
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
            "Duplicated authorization checks lead to policy drift and inconsistent permission boundaries."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Extract repeated role or permission verification into centralized authorization middleware."
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
            rationale="Repeated inline authorization checks increase security regression risks during updates.",
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
            if any(ev.evidence_kind == "inline_authz_check" for ev in e.authz_evidence)
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
                f"Repeated inline authorization checks detected across {len(inline_eps)} endpoints: "
                f"({', '.join(peer_routes)}). Role verification logic should be factored into reusable guards."
            )
            sig = f"{context.file_path}:duplicated_inline_authz"
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
