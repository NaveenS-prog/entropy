"""Static route and security pattern detector for JavaScript and TypeScript web frameworks.

Inspects parsed JSTSASTContext to extract normalized EndpointDefinitions across
Express, Fastify, and Next.js applications.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.analyzers.jsts_context import JSTSASTContext
from app.analyzers.security.models import (
    PUBLIC_EXACT_PATHS,
    AuthenticationEvidence,
    AuthMechanismType,
    AuthorizationEvidence,
    AuthzMechanismType,
    EndpointDefinition,
    WebFramework,
)
from app.models.domain.enums import Confidence
from app.parser.python.models import SourceLocation
from app.scoring.weights import SENSITIVE_ROUTE_TERMS

# Auth-related keyword patterns for middleware identification
AUTH_MIDDLEWARE_PATTERNS = [
    r"\bauth\b",
    r"authenticate",
    r"requireauth",
    r"isauthenticated",
    r"ensureauthenticated",
    r"verifytoken",
    r"verifyjwt",
    r"checkauth",
    r"jwtauth",
    r"\bprotect\b",
    r"passport",
    r"sessionauth",
    r"withauth",
    r"clerk",
    r"supabaseauth",
]

# Authz-related keyword patterns for middleware identification
AUTHZ_MIDDLEWARE_PATTERNS = [
    r"requireadmin",
    r"adminonly",
    r"checkrole",
    r"hasrole",
    r"haspermission",
    r"\bauthorize\b",
    r"checkpermission",
    r"canaccess",
    r"roleguard",
    r"adminguard",
    r"\bpermit\b",
    r"allowrole",
]

# Inline authentication indicators in handler source text
INLINE_AUTH_PATTERNS = [
    r"jwt\.verify\(",
    r"verifytoken\(",
    r"verifyjwt\(",
    r"req(?:uest)?\.user\b",
    r"req(?:uest)?\.auth\b",
    r"req(?:uest)?\.session\.user(?:id)?",
    r"getserversession\(",
    r"supabase\.auth\.getuser\(",
    r"\bauth\(\)",
    r"req(?:uest)?\.headers(?:\.authorization|\['authorization'\]|\[\"authorization\"\])",
]

# Inline authorization indicators in handler source text
INLINE_AUTHZ_PATTERNS = [
    r"req(?:uest)?\.user\.role\b",
    r"req(?:uest)?\.user\.roles\b",
    r"user\.isadmin\b",
    r"req(?:uest)?\.user\.isadmin\b",
    r"haspermission\(",
    r"\bcan\(",
    r"\.role\s*===?\s*['\"`]admin['\"`]",
    r"\.roles\.includes\(",
]

# Public route middleware patterns
PUBLIC_MIDDLEWARE_PATTERNS = [
    r"\bpublic\b",
    r"allowanon",
    r"noauth",
    r"optionalauth",
]


class JSFrameworkRouteDetector:
    """Extracts normalized EndpointDefinitions from parsed JavaScript/TypeScript AST contexts."""

    @classmethod
    def extract_endpoints(cls, context: JSTSASTContext) -> list[EndpointDefinition]:
        endpoints: list[EndpointDefinition] = []
        routes = context.get_routes()
        if not routes:
            return []

        # Check for file-level auth middleware in Express: e.g. app.use(auth) or router.use(auth)
        file_level_auth: list[AuthenticationEvidence] = []
        file_level_authz: list[AuthorizationEvidence] = []

        for call in context.get_calls():
            if call.method_name == "use" and call.caller_object:
                caller_lower = call.caller_object.lower()
                if any(k in caller_lower for k in ("app", "router", "server")):
                    for arg in call.arguments:
                        arg_lower = arg.lower()
                        if any(re.search(p, arg_lower) for p in AUTH_MIDDLEWARE_PATTERNS):
                            loc = SourceLocation(
                                line_start=call.location.line_start,
                                line_end=call.location.line_end,
                                col_offset=call.location.col_start,
                                end_col_offset=call.location.col_end,
                            )
                            file_level_auth.append(
                                AuthenticationEvidence(
                                    mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                                    source_location=loc,
                                    endpoint="*",
                                    guard_name=arg,
                                    evidence_kind="file_middleware",
                                    confidence=Confidence.HIGH,
                                    details=f"File-level middleware '{arg}' applied via {call.callee}",
                                )
                            )
                        if any(re.search(p, arg_lower) for p in AUTHZ_MIDDLEWARE_PATTERNS):
                            loc = SourceLocation(
                                line_start=call.location.line_start,
                                line_end=call.location.line_end,
                                col_offset=call.location.col_start,
                                end_col_offset=call.location.col_end,
                            )
                            file_level_authz.append(
                                AuthorizationEvidence(
                                    mechanism_type=AuthzMechanismType.ROLE_CHECK,
                                    source_location=loc,
                                    endpoint="*",
                                    role_or_permission=arg,
                                    evidence_kind="file_middleware",
                                    confidence=Confidence.HIGH,
                                    details=f"File-level authorization middleware '{arg}' applied via {call.callee}",
                                )
                            )

        for route in routes:
            framework = cls._map_framework(route.framework)
            symbol = route.handler_name or f"{route.http_method}_{route.path.replace('/', '_').strip('_') or 'root'}"
            loc = SourceLocation(
                line_start=route.location.line_start,
                line_end=route.location.line_end,
                col_offset=route.location.col_start,
                end_col_offset=route.location.col_end,
            )

            # Public check
            is_public, public_reasons = cls._evaluate_public(route)

            # Security sensitivity check
            is_sensitive, sensitivity_reasons = cls._evaluate_sensitivity(route, symbol)

            # Route group calculation
            route_group = cls._compute_route_group(route.path, context.file_path)

            # Evidence collection
            auth_evidence = list(file_level_auth)
            authz_evidence = list(file_level_authz)

            # Check middleware on route
            for mw in route.middleware:
                mw_lower = mw.lower()
                is_auth_mw = any(re.search(p, mw_lower) for p in AUTH_MIDDLEWARE_PATTERNS)
                is_authz_mw = any(re.search(p, mw_lower) for p in AUTHZ_MIDDLEWARE_PATTERNS)

                if is_auth_mw:
                    auth_evidence.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                            source_location=loc,
                            endpoint=route.path,
                            guard_name=mw,
                            evidence_kind="route_middleware",
                            confidence=Confidence.HIGH,
                            details=f"Route middleware '{mw}' enforces authentication",
                        )
                    )
                if is_authz_mw:
                    authz_evidence.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.ROLE_CHECK,
                            source_location=loc,
                            endpoint=route.path,
                            role_or_permission=mw,
                            evidence_kind="route_middleware",
                            confidence=Confidence.HIGH,
                            details=f"Route middleware '{mw}' enforces authorization",
                        )
                    )
                    # Authz middleware (e.g. requireAdmin) also inherently verifies authentication
                    if not is_auth_mw:
                        auth_evidence.append(
                            AuthenticationEvidence(
                                mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                                source_location=loc,
                                endpoint=route.path,
                                guard_name=mw,
                                evidence_kind="authz_implied_auth",
                                confidence=Confidence.HIGH,
                                details=f"Authorization middleware '{mw}' implies authenticated caller",
                            )
                        )

            # Check handler body or verbatim line span of route call
            handler_text = ""
            if 1 <= route.location.line_start <= len(context.lines):
                end_line = min(
                    len(context.lines),
                    max(route.location.line_start, route.location.line_end),
                )
                handler_text = "\n".join(context.lines[route.location.line_start - 1 : end_line])

            handler_fn = None
            if route.handler_name:
                handler_fn = context.get_function(route.handler_name)
            if not handler_fn:
                for fn in context.get_functions():
                    if fn.location.line_start == route.location.line_start:
                        handler_fn = fn
                        break

            combined_text = (handler_text + "\n" + (handler_fn.body_text if handler_fn else "")).lower()

            for pattern in INLINE_AUTH_PATTERNS:
                m = re.search(pattern, combined_text)
                if m:
                    auth_evidence.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.GUARD_CALL,
                            source_location=loc,
                            endpoint=route.path,
                            guard_name=m.group(0),
                            evidence_kind="inline_auth_check",
                            confidence=Confidence.HIGH,
                            details=f"Inline authentication check '{m.group(0)}' in handler body",
                        )
                    )
                    break

            for pattern in INLINE_AUTHZ_PATTERNS:
                m = re.search(pattern, combined_text)
                if m:
                    authz_evidence.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.ROLE_CHECK,
                            source_location=loc,
                            endpoint=route.path,
                            role_or_permission=m.group(0),
                            evidence_kind="inline_authz_check",
                            confidence=Confidence.HIGH,
                            details=f"Inline authorization check '{m.group(0)}' in handler body",
                        )
                    )
                    break

            endpoint = EndpointDefinition(
                symbol=symbol,
                file_path=context.file_path,
                location=loc,
                http_methods=[route.http_method],
                route_path=route.path,
                framework=framework,
                is_security_sensitive=is_sensitive,
                sensitivity_reasons=sensitivity_reasons,
                is_public=is_public,
                public_reasons=public_reasons,
                auth_evidence=auth_evidence,
                authz_evidence=authz_evidence,
                route_group=route_group,
                metadata={
                    "framework": route.framework,
                    "middleware": route.middleware,
                    "handler_name": route.handler_name,
                },
            )
            endpoints.append(endpoint)

        return endpoints

    @classmethod
    def _map_framework(cls, framework_str: str) -> WebFramework:
        f_lower = (framework_str or "").lower()
        if "express" in f_lower:
            return WebFramework.EXPRESS
        if "fastify" in f_lower:
            return WebFramework.FASTIFY
        if "next" in f_lower:
            return WebFramework.NEXTJS
        if "nest" in f_lower:
            return WebFramework.NESTJS
        return WebFramework.GENERIC

    @classmethod
    def _evaluate_public(cls, route) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        path_norm = route.path.rstrip("/").lower()
        if path_norm in PUBLIC_EXACT_PATHS or path_norm == "":
            reasons.append(f"Standard public path '{route.path}'")

        for mw in route.middleware:
            mw_lower = mw.lower()
            if any(re.search(p, mw_lower) for p in PUBLIC_MIDDLEWARE_PATTERNS):
                reasons.append(f"Explicit public middleware '{mw}'")

        return bool(reasons), reasons

    @classmethod
    def _evaluate_sensitivity(cls, route, symbol: str) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        path_lower = route.path.lower()
        sym_lower = symbol.lower()
        combined = f"{path_lower} {sym_lower}"

        matched_terms = [t for t in SENSITIVE_ROUTE_TERMS if t in combined]
        if matched_terms:
            reasons.append(f"Sensitive terms ({', '.join(sorted(matched_terms)[:3])})")

        if any(seg in path_lower for seg in ("/admin", "/manage", "/roles", "/privileges", "/system")):
            reasons.append("Administrative path")

        if any(seg in path_lower for seg in ("/payment", "/refund", "/billing", "/checkout")):
            reasons.append("Financial / Payment path")

        if route.http_method in ("POST", "PUT", "DELETE", "PATCH") and (matched_terms or reasons):
            reasons.append(f"Mutating method {route.http_method}")

        return bool(reasons), reasons

    @classmethod
    def _compute_route_group(cls, route_path: str, file_path: str) -> str:
        file_stem = Path(file_path).stem
        if not route_path:
            return file_stem
        parts = [p for p in route_path.strip("/").split("/") if p and not p.startswith(":")]
        if len(parts) >= 2 and parts[0] == "api":
            return "/" + "/".join(parts[:3])
        elif parts:
            return f"/{parts[0]}"
        return file_stem
