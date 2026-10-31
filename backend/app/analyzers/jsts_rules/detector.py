"""Static route and security pattern detector for JavaScript and TypeScript web frameworks.

Inspects parsed JSTSASTContext to extract normalized EndpointDefinitions across
Express, Fastify, and Next.js applications.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
from app.scoring.weights import (
    SENSITIVE_ROUTE_TERMS,
    STATE_CHANGING_METHODS,
    STATE_CHANGING_PUBLIC_ALLOWLIST,
    match_intentionally_public_endpoint,
)

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


@dataclass
class FileMiddlewareRegistration:
    callee: str
    caller_object: str | None
    middleware_name: str
    mount_path: str | None
    line_start: int
    line_end: int
    is_auth: bool
    is_authz: bool
    confidence: Confidence
    details: str


class JSFrameworkRouteDetector:
    """Extracts normalized EndpointDefinitions from parsed JavaScript/TypeScript AST contexts."""

    @classmethod
    def _is_trivial_passthrough(cls, body_text: str) -> bool:
        """Return True if function body is trivially a pass-through (only calls next()/returns without checks)."""
        cleaned = re.sub(r"/\*.*?\*/", "", body_text, flags=re.DOTALL)
        cleaned = re.sub(r"//.*", "", cleaned)
        cleaned = cleaned.strip()

        # Check for presence of real security, token, session, header, user access or conditionals
        has_security_check = any(
            term in cleaned.lower()
            for term in (
                "token",
                "jwt",
                "session",
                "header",
                "headers",
                "req.user",
                "request.user",
                "req.auth",
                "request.auth",
                "status(401)",
                "status(403)",
                "401",
                "403",
                "unauthorized",
                "forbidden",
                "if (",
                "if(",
                "throw ",
                "reject(",
                "catch",
                "cookie",
                "cookies",
                "bearer",
            )
        )
        if has_security_check:
            return False

        # If no security checks or conditions, inspect if it just returns or calls next()
        norm = re.sub(r"[\s{};()]+", "", cleaned.lower())
        return norm in ("next", "returnnext", "return", "")

    @classmethod
    def _register_file_middleware(
        cls,
        context: JSTSASTContext,
        mw_name: str,
        call: Any,
        mount_path: str | None,
        registrations: list[FileMiddlewareRegistration],
    ) -> None:
        mw_lower = mw_name.lower()
        is_auth_name = any(re.search(p, mw_lower) for p in AUTH_MIDDLEWARE_PATTERNS)
        is_authz_name = any(re.search(p, mw_lower) for p in AUTHZ_MIDDLEWARE_PATTERNS)

        # Check if mw is an inline function
        is_inline_fn = mw_name.startswith("(") or mw_name.startswith("function") or "=>" in mw_name
        if is_inline_fn:
            if cls._is_trivial_passthrough(mw_name):
                return
            registrations.append(
                FileMiddlewareRegistration(
                    callee=call.callee,
                    caller_object=call.caller_object,
                    middleware_name="inline_middleware",
                    mount_path=mount_path,
                    line_start=call.location.line_start,
                    line_end=call.location.line_end,
                    is_auth=True,
                    is_authz=is_authz_name,
                    confidence=Confidence.HIGH,
                    details=f"Inline middleware verified with AST inspection applied via {call.callee}",
                )
            )
            return

        # Check if identifier can be resolved in the same file
        fn = context.get_function(mw_name)
        if fn is not None:
            if cls._is_trivial_passthrough(fn.body_text):
                return
            is_auth = (
                is_auth_name
                or any(re.search(p, fn.body_text.lower()) for p in INLINE_AUTH_PATTERNS)
                or "jwt" in fn.body_text.lower()
                or "token" in fn.body_text.lower()
            )
            is_authz = (
                is_authz_name
                or any(re.search(p, fn.body_text.lower()) for p in INLINE_AUTHZ_PATTERNS)
                or "role" in fn.body_text.lower()
                or "admin" in fn.body_text.lower()
            )
            if is_auth or is_authz:
                registrations.append(
                    FileMiddlewareRegistration(
                        callee=call.callee,
                        caller_object=call.caller_object,
                        middleware_name=mw_name,
                        mount_path=mount_path,
                        line_start=call.location.line_start,
                        line_end=call.location.line_end,
                        is_auth=is_auth,
                        is_authz=is_authz,
                        confidence=Confidence.HIGH,
                        details=f"Middleware '{mw_name}' verified with AST body inspection applied via {call.callee}",
                    )
                )
            return

        # Unresolved identifier (imported from another module)
        if is_auth_name or is_authz_name:
            registrations.append(
                FileMiddlewareRegistration(
                    callee=call.callee,
                    caller_object=call.caller_object,
                    middleware_name=mw_name,
                    mount_path=mount_path,
                    line_start=call.location.line_start,
                    line_end=call.location.line_end,
                    is_auth=is_auth_name,
                    is_authz=is_authz_name,
                    confidence=Confidence.MEDIUM,
                    details=f"Name-only middleware '{mw_name}' (imported or unresolved in this file); confidence lowered to MEDIUM",
                )
            )

    @classmethod
    def extract_endpoints(cls, context: JSTSASTContext) -> list[EndpointDefinition]:
        endpoints: list[EndpointDefinition] = []
        routes = context.get_routes()
        if not routes:
            return []

        # Collect file-level middleware registrations in order
        file_middleware_regs: list[FileMiddlewareRegistration] = []

        for call in context.get_calls():
            if call.method_name == "use" and call.caller_object:
                caller_lower = call.caller_object.lower()
                if any(k in caller_lower for k in ("app", "router", "server")):
                    args = list(call.arguments)
                    if not args:
                        continue
                    mount_path: str | None = None
                    first_arg = args[0].strip()
                    if (
                        (first_arg.startswith("'") or first_arg.startswith('"') or first_arg.startswith("`"))
                        and (first_arg.strip("'\"`").startswith("/") or first_arg.strip("'\"`") == "*")
                    ):
                        mount_path = first_arg.strip("'\"`")
                        mw_args = args[1:]
                    else:
                        mw_args = args

                    for arg in mw_args:
                        arg_clean = arg.strip().strip("'\"`")
                        cls._register_file_middleware(
                            context=context,
                            mw_name=arg_clean,
                            call=call,
                            mount_path=mount_path,
                            registrations=file_middleware_regs,
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
            is_public, public_reasons, matched_pat = cls._evaluate_public(route)

            # Security sensitivity check
            is_sensitive, sensitivity_reasons = cls._evaluate_sensitivity(route, symbol)

            # Route group calculation
            route_group = cls._compute_route_group(route.path, context.file_path)

            # Evidence collection: apply file-level middleware only to routes registered AFTER it and within mount path
            auth_evidence: list[AuthenticationEvidence] = []
            authz_evidence: list[AuthorizationEvidence] = []

            for reg in file_middleware_regs:
                # Registration order check
                if route.location.line_start <= reg.line_start:
                    continue
                # Mount path check
                if reg.mount_path:
                    m_path = reg.mount_path.rstrip("/")
                    r_path = route.path.rstrip("/")
                    if m_path != "*" and not (r_path == m_path or r_path.startswith(m_path + "/")):
                        continue

                mw_loc = SourceLocation(
                    line_start=reg.line_start,
                    line_end=reg.line_end,
                    col_offset=0,
                    end_col_offset=0,
                )
                if reg.is_auth:
                    auth_evidence.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                            source_location=mw_loc,
                            endpoint=route.path,
                            guard_name=reg.middleware_name,
                            evidence_kind="file_middleware",
                            confidence=reg.confidence,
                            details=reg.details,
                        )
                    )
                if reg.is_authz:
                    authz_evidence.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.ROLE_CHECK,
                            source_location=mw_loc,
                            endpoint=route.path,
                            role_or_permission=reg.middleware_name,
                            evidence_kind="file_middleware",
                            confidence=reg.confidence,
                            details=reg.details,
                        )
                    )
                    if not reg.is_auth:
                        auth_evidence.append(
                            AuthenticationEvidence(
                                mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                                source_location=mw_loc,
                                endpoint=route.path,
                                guard_name=reg.middleware_name,
                                evidence_kind="authz_implied_auth",
                                confidence=reg.confidence,
                                details=f"Authorization middleware '{reg.middleware_name}' implies authenticated caller",
                            )
                        )

            # If NestJS route, inspect class- and method-level decorators
            if route.framework == "nestjs":
                enclosing_cls = None
                cls_method = None
                for c in context.get_classes():
                    for m in c.methods:
                        if m.name == route.handler_name or (m.location.line_start <= route.location.line_start <= m.location.line_end):
                            enclosing_cls = c
                            cls_method = m
                            break
                    if enclosing_cls:
                        break

                all_decs = (enclosing_cls.decorators if enclosing_cls else []) + (cls_method.decorators if cls_method else [])

                # Check for @Public()
                for d in all_decs:
                    if re.search(r"\bpublic\b", d, re.IGNORECASE) or "ispublic" in d.lower():
                        eval_override = match_intentionally_public_endpoint(
                            route.path, route.handler_name, http_method=route.http_method
                        )
                        if eval_override.deny_term:
                            is_public = False
                            public_reasons = [
                                f"Denied public status due to sensitive term '{eval_override.deny_term}' in route or handler"
                            ]
                        else:
                            is_public = True
                            public_reasons.append(f"NestJS @{d} decorator marks endpoint public")

                # Check for @UseGuards(...)
                for d in all_decs:
                    gm = re.match(r"^UseGuards\s*\(([^)]*)\)", d)
                    if gm:
                        guard_args = [g.strip().strip("'\"`") for g in gm.group(1).split(",") if g.strip()]
                        for g in guard_args:
                            auth_evidence.append(
                                AuthenticationEvidence(
                                    mechanism_type=AuthMechanismType.GUARD_CALL,
                                    source_location=loc,
                                    endpoint=route.path,
                                    guard_name=g,
                                    evidence_kind="guard_decorator",
                                    confidence=Confidence.HIGH,
                                    details=f"NestJS guard '{g}' enforces authentication",
                                )
                            )
                            if any(k in g.lower() for k in ("role", "admin", "permission", "authz")):
                                authz_evidence.append(
                                    AuthorizationEvidence(
                                        mechanism_type=AuthzMechanismType.ROLE_CHECK,
                                        source_location=loc,
                                        endpoint=route.path,
                                        role_or_permission=g,
                                        evidence_kind="guard_decorator",
                                        confidence=Confidence.HIGH,
                                        details=f"NestJS role guard '{g}' enforces authorization",
                                    )
                                )

                # Check for @Roles(...)
                for d in all_decs:
                    rm = re.match(r"^Roles\s*\(([^)]*)\)", d)
                    if rm:
                        roles = [r.strip().strip("'\"`") for r in rm.group(1).split(",") if r.strip()]
                        roles_str = ", ".join(roles)
                        authz_evidence.append(
                            AuthorizationEvidence(
                                mechanism_type=AuthzMechanismType.ROLE_CHECK,
                                source_location=loc,
                                endpoint=route.path,
                                role_or_permission=roles_str,
                                evidence_kind="role_decorator",
                                confidence=Confidence.HIGH,
                                details=f"NestJS @Roles({roles_str}) enforces authorization",
                            )
                        )
                        auth_evidence.append(
                            AuthenticationEvidence(
                                mechanism_type=AuthMechanismType.GUARD_CALL,
                                source_location=loc,
                                endpoint=route.path,
                                guard_name=f"Roles({roles_str})",
                                evidence_kind="authz_implied_auth",
                                confidence=Confidence.HIGH,
                                details=f"NestJS @Roles({roles_str}) implies authenticated caller",
                            )
                        )

            # Check middleware on route
            for mw in route.middleware:
                mw_lower = mw.lower()
                is_auth_name = any(re.search(p, mw_lower) for p in AUTH_MIDDLEWARE_PATTERNS)
                is_authz_name = any(re.search(p, mw_lower) for p in AUTHZ_MIDDLEWARE_PATTERNS)

                is_inline_fn = mw.startswith("(") or mw.startswith("function") or "=>" in mw
                if is_inline_fn:
                    if cls._is_trivial_passthrough(mw):
                        continue
                    auth_evidence.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                            source_location=loc,
                            endpoint=route.path,
                            guard_name="inline_middleware",
                            evidence_kind="route_middleware",
                            confidence=Confidence.HIGH,
                            details="Inline route middleware verified with AST inspection",
                        )
                    )
                    if is_authz_name:
                        authz_evidence.append(
                            AuthorizationEvidence(
                                mechanism_type=AuthzMechanismType.ROLE_CHECK,
                                source_location=loc,
                                endpoint=route.path,
                                role_or_permission="inline_middleware",
                                evidence_kind="route_middleware",
                                confidence=Confidence.HIGH,
                                details="Inline authorization middleware verified with AST inspection",
                            )
                        )
                    continue

                fn = context.get_function(mw)
                if fn is not None:
                    if cls._is_trivial_passthrough(fn.body_text):
                        continue
                    is_auth = (
                        is_auth_name
                        or any(re.search(p, fn.body_text.lower()) for p in INLINE_AUTH_PATTERNS)
                        or "jwt" in fn.body_text.lower()
                        or "token" in fn.body_text.lower()
                    )
                    is_authz = (
                        is_authz_name
                        or any(re.search(p, fn.body_text.lower()) for p in INLINE_AUTHZ_PATTERNS)
                        or "role" in fn.body_text.lower()
                        or "admin" in fn.body_text.lower()
                    )
                    if is_auth:
                        auth_evidence.append(
                            AuthenticationEvidence(
                                mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                                source_location=loc,
                                endpoint=route.path,
                                guard_name=mw,
                                evidence_kind="route_middleware",
                                confidence=Confidence.HIGH,
                                details=f"Route middleware '{mw}' verified with AST body inspection",
                            )
                        )
                    if is_authz:
                        authz_evidence.append(
                            AuthorizationEvidence(
                                mechanism_type=AuthzMechanismType.ROLE_CHECK,
                                source_location=loc,
                                endpoint=route.path,
                                role_or_permission=mw,
                                evidence_kind="route_middleware",
                                confidence=Confidence.HIGH,
                                details=f"Route authorization middleware '{mw}' verified with AST body inspection",
                            )
                        )
                        if not is_auth:
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
                    continue

                if is_auth_name:
                    auth_evidence.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                            source_location=loc,
                            endpoint=route.path,
                            guard_name=mw,
                            evidence_kind="route_middleware",
                            confidence=Confidence.MEDIUM,
                            details=f"Name-only route middleware '{mw}' (imported or unresolved in this file); confidence lowered to MEDIUM",
                        )
                    )
                if is_authz_name:
                    authz_evidence.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.ROLE_CHECK,
                            source_location=loc,
                            endpoint=route.path,
                            role_or_permission=mw,
                            evidence_kind="route_middleware",
                            confidence=Confidence.MEDIUM,
                            details=f"Name-only authorization middleware '{mw}' (imported or unresolved in this file); confidence lowered to MEDIUM",
                        )
                    )
                    if not is_auth_name:
                        auth_evidence.append(
                            AuthenticationEvidence(
                                mechanism_type=AuthMechanismType.MIDDLEWARE_REFERENCE,
                                source_location=loc,
                                endpoint=route.path,
                                guard_name=mw,
                                evidence_kind="authz_implied_auth",
                                confidence=Confidence.MEDIUM,
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
                    **({"public_pattern": matched_pat} if matched_pat else {}),
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
        if "hono" in f_lower:
            return WebFramework.HONO
        return WebFramework.GENERIC

    @classmethod
    def _evaluate_public(cls, route) -> tuple[bool, list[str], str | None]:
        reasons: list[str] = []
        path_norm = route.path.rstrip("/").lower()
        http_method = getattr(route, "http_method", None)

        eval_res = match_intentionally_public_endpoint(
            route_path=route.path,
            handler_name=route.handler_name,
            http_method=http_method,
        )

        if eval_res.deny_term:
            return (
                False,
                [f"Denied public status due to sensitive term '{eval_res.deny_term}' in route or handler"],
                None,
            )

        mutating = {http_method.upper()} if http_method and http_method.upper() in STATE_CHANGING_METHODS else set()
        if mutating:
            has_sc_allow = any(term in path_norm for term in STATE_CHANGING_PUBLIC_ALLOWLIST)
            if not has_sc_allow:
                return (
                    False,
                    [f"State-changing method ({', '.join(sorted(mutating))}) not allowed on public endpoint '{route.path}'"],
                    None,
                )

        matched_pattern = eval_res.matched_pattern
        if eval_res.is_public and matched_pattern:
            reasons.append(f"Intentionally public route pattern '{matched_pattern}' in '{route.path}'")

        if path_norm in PUBLIC_EXACT_PATHS or path_norm == "":
            reasons.append(f"Standard public path '{route.path}'")

        for mw in route.middleware:
            mw_lower = mw.lower()
            if any(re.search(p, mw_lower) for p in PUBLIC_MIDDLEWARE_PATTERNS):
                reasons.append(f"Explicit public middleware '{mw}'")

        # Standard user registration / signup POST endpoints
        if route.http_method == "POST" and path_norm in ("/users", "/user", "/api/users", "/api/v1/users"):
            reasons.append(f"Standard public user registration POST '{route.path}'")

        is_public = len(reasons) > 0
        return is_public, reasons, matched_pattern

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
