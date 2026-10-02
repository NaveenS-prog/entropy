"""Static Framework-Aware Web Route and Security Pattern Detector.

Operates purely via static AST analysis without executing repository code, importing modules,
or initiating web servers.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from app.analyzers.context import PythonASTContext
from app.analyzers.security.models import (
    AuthenticationEvidence,
    AuthMechanismType,
    AuthorizationEvidence,
    AuthzMechanismType,
    EndpointDefinition,
    WebFramework,
)
from app.models.domain.enums import Confidence
from app.parser.python.models import Decorator, FunctionDefinition, SourceLocation

# Keywords indicating potential security sensitivity
SENSITIVE_ROUTE_TERMS = {
    "admin",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "setting",
    "settings",
    "password",
    "passwords",
    "secret",
    "secrets",
    "key",
    "keys",
    "credential",
    "credentials",
    "token",
    "tokens",
    "payment",
    "payments",
    "billing",
    "checkout",
    "finance",
    "invoice",
    "invoices",
    "order",
    "orders",
    "privilege",
    "privileges",
    "role",
    "roles",
    "permission",
    "permissions",
    "audit",
    "audits",
    "security",
    "config",
    "configuration",
    "manage",
    "management",
    "internal",
    "private",
    "sensitive",
    "upload",
    "export",
    "delete",
    "destroy",
    "purge",
    "update",
    "create",
    "grant",
    "revoke",
    "transfer",
}

# Public endpoints that are intentionally unauthenticated
PUBLIC_EXACT_PATHS = {
    "",
    "/",
    "/health",
    "/healthz",
    "/live",
    "/ready",
    "/ping",
    "/status",
    "/metrics",
    "/info",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/token",
    "/auth/token",
    "/oauth/token",
    "/forgot-password",
    "/reset-password",
    "/auth/login",
    "/api/login",
}

PUBLIC_PREFIXES = ("/public/", "/static/", "/assets/", "/docs/", "/redoc/")

# Non-route decorator indicators (to eliminate CLI, tasks, tests)
NON_ROUTE_DECORATOR_MARKERS = {
    "click.command",
    "click.group",
    "cli.command",
    "command",
    "task",
    "celery.task",
    "shared_task",
    "pytest.fixture",
    "fixture",
    "classmethod",
    "staticmethod",
    "property",
}

# Known authentication guard names
KNOWN_AUTH_GUARDS = {
    "login_required",
    "auth_required",
    "require_auth",
    "requires_auth",
    "jwt_required",
    "token_required",
    "authenticate",
    "authenticated",
    "verify_token",
    "verify_jwt",
    "get_current_user",
    "get_current_active_user",
    "get_user",
    "current_user",
    "oauth2_scheme",
    "http_bearer",
    "api_key",
    "api_key_auth",
    "auth",
}

# Known authorization guard / decorator names
KNOWN_AUTHZ_GUARDS = {
    "permission_required",
    "permissions_required",
    "roles_required",
    "role_required",
    "require_role",
    "require_roles",
    "requires_role",
    "roles_accepted",
    "has_role",
    "has_permission",
    "user_passes_test",
    "authorize",
    "authorized",
    "is_admin",
    "admin_required",
    "verify_admin",
    "check_admin_role",
    "require_superuser",
    "check_permission",
    "check_role",
}


class FrameworkRouteDetector:
    """Detects web endpoints and extracts observable authentication and authorization evidence."""

    @classmethod
    def detect_framework(cls, context: PythonASTContext) -> WebFramework:
        """Infer web framework from static imports and syntax."""
        imports = context.get_imports()
        modules = {imp.module or "" for imp in imports}
        names = {imp.name for imp in imports}

        if any("fastapi" in m for m in modules) or "FastAPI" in names or "APIRouter" in names:
            return WebFramework.FASTAPI
        if any("flask" in m for m in modules) or "Flask" in names or "Blueprint" in names:
            return WebFramework.FLASK
        if any("django" in m for m in modules) or "urlpatterns" in [
            a.targets[0] for a in context.get_assignments() if a.targets
        ]:
            return WebFramework.DJANGO

        # Secondary check: Decorator patterns in file
        for dec in context.get_decorators():
            dname = dec.name.lower()
            if any(
                dname.startswith(p)
                for p in ("app.get", "app.post", "router.get", "router.post", "api_router.get")
            ):
                return WebFramework.FASTAPI
            if dname.startswith("app.route") or dname.startswith("bp.route"):
                return WebFramework.FLASK

        return WebFramework.UNKNOWN

    @classmethod
    def extract_endpoints(cls, context: PythonASTContext) -> list[EndpointDefinition]:
        """Extract all observable web endpoints defined in a parsed Python context."""
        framework = cls.detect_framework(context)
        endpoints: list[EndpointDefinition] = []

        # Find raw AST functions for body inspection
        ast_func_map: dict[tuple[str, int], ast.AST] = {}
        if context.ast_root:
            for node in ast.walk(context.ast_root):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    ast_func_map[(node.name, getattr(node, "lineno", 0))] = node

        for func in context.get_functions():
            # Filter out non-route functions
            if cls._is_non_route_function(func):
                continue

            endpoint = cls._inspect_function_as_endpoint(context, func, framework, ast_func_map)
            if endpoint:
                endpoints.append(endpoint)

        # Check Django Class-Based Views
        if framework == WebFramework.DJANGO or framework == WebFramework.UNKNOWN:
            cbv_endpoints = cls._inspect_django_cbvs(context, ast_func_map)
            endpoints.extend(cbv_endpoints)

        # Infer route groups for consistency clustering
        cls._assign_route_groups(context.file_path, endpoints)

        return endpoints

    @classmethod
    def _is_non_route_function(cls, func: FunctionDefinition) -> bool:
        """Heuristically ensure CLI commands, tasks, test functions, and helpers are excluded."""
        # Test functions
        if func.name.startswith("test_") or func.name == "setup" or func.name == "teardown":
            return True

        # Non-route decorators
        for dec in func.decorators:
            dname = dec.name.lower()
            if any(marker in dname for marker in NON_ROUTE_DECORATOR_MARKERS):
                return True

        # Private helpers with no decorators
        if func.name.startswith("_") and not func.decorators:
            return True

        return False

    @classmethod
    def _inspect_function_as_endpoint(
        cls,
        context: PythonASTContext,
        func: FunctionDefinition,
        framework: WebFramework,
        ast_func_map: dict[tuple[str, int], ast.AST],
    ) -> EndpointDefinition | None:
        """Inspect a single function definition for web route signatures."""
        route_decorator: Decorator | None = None
        http_methods: list[str] = []
        route_path: str | None = None
        detected_fw = framework

        # 1. Check Decorators
        for dec in func.decorators:
            dname = dec.name.lower()
            dexpr = dec.expression.lower()

            # FastAPI decorator matching
            fastapi_match = re.search(
                r"(?:app|router|api_router|auth_router|admin_router|blueprint|v1_router)\.(get|post|put|delete|patch|api_route|websocket)",
                dexpr,
            )
            if fastapi_match:
                route_decorator = dec
                detected_fw = WebFramework.FASTAPI
                method = fastapi_match.group(1).upper()
                if method == "API_ROUTE":
                    http_methods = cls._extract_methods_from_kwargs(dec) or ["GET"]
                else:
                    http_methods = [method]
                route_path = cls._extract_path_from_args(dec)
                break

            # Flask decorator matching
            if any(
                p in dexpr
                for p in ("app.route", "bp.route", "blueprint.route", "api.route", ".route")
            ):
                route_decorator = dec
                detected_fw = WebFramework.FLASK
                http_methods = cls._extract_methods_from_kwargs(dec) or ["GET"]
                route_path = cls._extract_path_from_args(dec)
                break
            flask_method_match = re.search(
                r"(?:app|bp|blueprint|api)\.(get|post|put|delete|patch)", dexpr
            )
            if flask_method_match:
                route_decorator = dec
                detected_fw = WebFramework.FLASK
                http_methods = [flask_method_match.group(1).upper()]
                route_path = cls._extract_path_from_args(dec)
                break

            # Django view decorator matching
            if dname in ("login_required", "permission_required", "user_passes_test"):
                # If decorated with django auth decorator and has 'request' param
                if any(p.name == "request" for p in func.parameters):
                    route_decorator = dec
                    detected_fw = WebFramework.DJANGO
                    http_methods = ["ANY"]
                    route_path = f"/{func.name.replace('_', '/')}"
                    break

        # Check Django URL patterns if not decorated
        if not route_decorator and detected_fw == WebFramework.DJANGO:
            django_path = cls._match_django_urlpatterns(context, func.name)
            if django_path:
                route_path = django_path
                http_methods = ["ANY"]
                detected_fw = WebFramework.DJANGO

        # If no route signature found, not an endpoint
        if not route_decorator and not route_path:
            return None

        # 2. Determine Sensitivity and Public Exclusions
        is_sensitive, sensitivity_reasons = cls._evaluate_sensitivity(
            func.name, route_path, http_methods
        )
        is_public, public_reasons = cls._evaluate_public_status(
            func.name, route_path, func.decorators
        )

        # 3. Extract Authentication Evidence
        raw_ast_node = ast_func_map.get((func.name, func.location.line_start))
        auth_evidences = cls._collect_auth_evidence(
            context, func, detected_fw, route_decorator, raw_ast_node
        )

        # 4. Extract Authorization Evidence
        authz_evidences = cls._collect_authz_evidence(
            context, func, detected_fw, route_decorator, raw_ast_node
        )

        return EndpointDefinition(
            symbol=func.qualified_name or func.name,
            file_path=context.file_path,
            location=func.location,
            http_methods=http_methods,
            route_path=route_path,
            framework=detected_fw,
            is_security_sensitive=is_sensitive,
            sensitivity_reasons=sensitivity_reasons,
            is_public=is_public,
            public_reasons=public_reasons,
            auth_evidence=auth_evidences,
            authz_evidence=authz_evidences,
            function_def=func,
        )

    @classmethod
    def _inspect_django_cbvs(
        cls,
        context: PythonASTContext,
        ast_func_map: dict[tuple[str, int], ast.AST],
    ) -> list[EndpointDefinition]:
        """Inspect Django Class-Based Views (View, APIView, ViewSet)."""
        endpoints: list[EndpointDefinition] = []
        http_method_names = {"get", "post", "put", "delete", "patch"}

        for cls_def in context.get_classes():
            is_view_class = any(
                b in ("View", "APIView", "ViewSet", "GenericAPIView", "ModelViewSet")
                or b.endswith("View")
                or b.endswith("ViewSet")
                for b in cls_def.base_classes
            )
            if not is_view_class:
                continue

            # Class-level auth / authz attributes
            class_auth_ev: list[AuthenticationEvidence] = []
            class_authz_ev: list[AuthorizationEvidence] = []

            for assign in cls_def.class_assignments:
                if "authentication_classes" in assign.targets:
                    class_auth_ev.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.GUARD_CALL,
                            source_location=assign.location,
                            endpoint=cls_def.name,
                            guard_name="authentication_classes",
                            evidence_kind="DJANGO_AUTH_CLASSES",
                            confidence=Confidence.HIGH,
                            details=f"authentication_classes defined on {cls_def.name}",
                        )
                    )
                if "permission_classes" in assign.targets:
                    # permission_classes can be auth (IsAuthenticated) or authz (IsAdminUser)
                    val_str = assign.value_representation or ""
                    if "IsAuthenticated" in val_str:
                        class_auth_ev.append(
                            AuthenticationEvidence(
                                mechanism_type=AuthMechanismType.GUARD_CALL,
                                source_location=assign.location,
                                endpoint=cls_def.name,
                                guard_name="IsAuthenticated",
                                evidence_kind="DJANGO_PERM_CLASSES",
                                confidence=Confidence.HIGH,
                                details="IsAuthenticated permission class",
                            )
                        )
                    if any(
                        term in val_str
                        for term in ("IsAdminUser", "IsStaff", "HasRole", "Permission")
                    ):
                        class_authz_ev.append(
                            AuthorizationEvidence(
                                mechanism_type=AuthMechanismType.DECORATOR,
                                source_location=assign.location,
                                endpoint=cls_def.name,
                                role_or_permission=val_str,
                                evidence_kind="DJANGO_AUTHZ_CLASSES",
                                confidence=Confidence.HIGH,
                                details="Administrative/Role permission class",
                            )
                        )

            # Methods inside CBV
            for method in cls_def.methods:
                if method.name.lower() in http_method_names:
                    method_name = method.name.upper()
                    route_path = f"/{cls_def.name.lower().removesuffix('view')}/{method.name.lower()}"
                    is_sensitive, sens_reasons = cls._evaluate_sensitivity(
                        method.name, route_path, [method_name]
                    )
                    is_public, pub_reasons = cls._evaluate_public_status(
                        method.name, route_path, method.decorators
                    )

                    raw_ast_node = ast_func_map.get((method.name, method.location.line_start))
                    m_auth_ev = list(class_auth_ev)
                    m_auth_ev.extend(
                        cls._collect_auth_evidence(
                            context, method, WebFramework.DJANGO, None, raw_ast_node
                        )
                    )
                    m_authz_ev = list(class_authz_ev)
                    m_authz_ev.extend(
                        cls._collect_authz_evidence(
                            context, method, WebFramework.DJANGO, None, raw_ast_node
                        )
                    )

                    endpoints.append(
                        EndpointDefinition(
                            symbol=f"{cls_def.name}.{method.name}",
                            file_path=context.file_path,
                            location=method.location,
                            http_methods=[method_name],
                            route_path=route_path,
                            framework=WebFramework.DJANGO,
                            is_security_sensitive=is_sensitive,
                            sensitivity_reasons=sens_reasons,
                            is_public=is_public,
                            public_reasons=pub_reasons,
                            auth_evidence=m_auth_ev,
                            authz_evidence=m_authz_ev,
                            enclosing_class=cls_def.name,
                            function_def=method,
                            class_def=cls_def,
                        )
                    )

        return endpoints

    @classmethod
    def _match_django_urlpatterns(cls, context: PythonASTContext, func_name: str) -> str | None:
        """Search urlpatterns assignments in the file for route mapping."""
        for assign in context.get_assignments("urlpatterns"):
            val = assign.value_representation or ""
            if func_name in val:
                # Extract path string before func_name if possible
                match = re.search(r'path\(\s*["\']([^"\']+)["\']\s*,\s*' + func_name, val)
                if match:
                    return f"/{match.group(1).strip('/')}"
                return f"/{func_name}"
        return None

    @classmethod
    def _extract_path_from_args(cls, dec: Decorator) -> str | None:
        """Extract route path string from decorator arguments."""
        if dec.arguments:
            first_arg = dec.arguments[0].strip("\"' ")
            if first_arg.startswith("/") or first_arg == "":
                return first_arg if first_arg.startswith("/") else f"/{first_arg}"
            # Even if it doesn't start with '/', treat as route path
            return f"/{first_arg}"
        if "path" in dec.keyword_arguments:
            p = dec.keyword_arguments["path"].strip("\"' ")
            return p if p.startswith("/") else f"/{p}"
        if "rule" in dec.keyword_arguments:
            r = dec.keyword_arguments["rule"].strip("\"' ")
            return r if r.startswith("/") else f"/{r}"
        return None

    @classmethod
    def _extract_methods_from_kwargs(cls, dec: Decorator) -> list[str]:
        """Extract HTTP methods list from methods kwarg."""
        raw = dec.keyword_arguments.get("methods", "")
        methods = []
        for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
            if m in raw.upper():
                methods.append(m)
        return methods

    @classmethod
    def _evaluate_sensitivity(
        cls,
        func_name: str,
        route_path: str | None,
        http_methods: list[str],
    ) -> tuple[bool, list[str]]:
        """Evaluate whether an endpoint is security sensitive."""
        reasons: list[str] = []
        path_lower = (route_path or "").lower()
        func_lower = func_name.lower()

        # Mutating methods are inherently sensitive
        for m in http_methods:
            if m in ("POST", "PUT", "DELETE", "PATCH"):
                reasons.append(f"State-modifying HTTP method ({m})")
                break

        # Check path terms
        path_tokens = set(re.findall(r"[a-zA-Z0-9]+", path_lower))
        matched_path_terms = path_tokens.intersection(SENSITIVE_ROUTE_TERMS)
        if matched_path_terms:
            reasons.append(f"Sensitive route keyword ({', '.join(sorted(matched_path_terms))})")

        # Check symbol/function terms
        func_tokens = set(re.findall(r"[a-zA-Z0-9]+", func_lower))
        matched_func_terms = func_tokens.intersection(SENSITIVE_ROUTE_TERMS)
        if matched_func_terms:
            reasons.append(f"Sensitive handler keyword ({', '.join(sorted(matched_func_terms))})")

        is_sensitive = len(reasons) > 0
        return is_sensitive, reasons

    @classmethod
    def _evaluate_public_status(
        cls,
        func_name: str,
        route_path: str | None,
        decorators: list[Decorator],
    ) -> tuple[bool, list[str]]:
        """Evaluate whether an endpoint is explicitly public / anonymous."""
        reasons: list[str] = []
        path_lower = (route_path or "").lower().rstrip("/")
        func_lower = func_name.lower()

        # Exact public path match
        if path_lower in PUBLIC_EXACT_PATHS or (route_path or "") in PUBLIC_EXACT_PATHS:
            reasons.append(f"Recognized public route '{route_path or '/'}'")

        # Public path prefix
        if any(path_lower.startswith(p.rstrip("/")) for p in PUBLIC_PREFIXES):
            reasons.append(f"Public prefix in route '{route_path}'")

        # Public decorators
        for dec in decorators:
            dname = dec.name.lower()
            if any(term in dname for term in ("public", "allow_anonymous", "permit_all")):
                reasons.append(f"Public decorator @{dec.name}")

        # Function name indicates public utility
        if func_lower in ("health", "health_check", "ping", "live", "ready", "public_index"):
            reasons.append(f"Public utility function name '{func_name}'")

        is_public = len(reasons) > 0
        return is_public, reasons

    @classmethod
    def _collect_auth_evidence(
        cls,
        context: PythonASTContext,
        func: FunctionDefinition,
        framework: WebFramework,
        route_decorator: Decorator | None,
        raw_ast_node: ast.AST | None,
    ) -> list[AuthenticationEvidence]:
        """Extract observable evidence of authentication checks on an endpoint."""
        evidences: list[AuthenticationEvidence] = []

        # 1. Parameter Dependencies (FastAPI)
        for param in func.parameters:
            default_val = param.default_value or ""
            if "Depends(" in default_val or "Security(" in default_val:
                # Check if param name or dependency target matches auth indicators
                p_lower = param.name.lower()
                def_lower = default_val.lower()
                is_auth_dep = (
                    any(term in p_lower for term in ("user", "auth", "token", "jwt", "cred", "admin", "principal", "actor", "account", "identity", "caller"))
                    or any(guard in def_lower for guard in KNOWN_AUTH_GUARDS)
                    or any(term in def_lower for term in ("require_", "verify_", "check_", "get_admin", "admin", "perm"))
                    or "security(" in def_lower
                )
                if is_auth_dep:
                    evidences.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.DEPENDENCY,
                            source_location=param.location or func.location,
                            endpoint=func.name,
                            guard_name=default_val,
                            evidence_kind="FASTAPI_PARAM_DEPENDENCY",
                            confidence=Confidence.HIGH,
                            details=f"Authentication dependency on parameter '{param.name}': {default_val}",
                        )
                    )

        # 2. Route Decorator Dependencies (FastAPI)
        if route_decorator and "dependencies" in route_decorator.keyword_arguments:
            dep_val = route_decorator.keyword_arguments["dependencies"]
            dep_lower = dep_val.lower()
            if any(guard in dep_lower for guard in KNOWN_AUTH_GUARDS) or "depends(" in dep_lower:
                evidences.append(
                    AuthenticationEvidence(
                        mechanism_type=AuthMechanismType.DEPENDENCY,
                        source_location=route_decorator.location,
                        endpoint=func.name,
                        guard_name=dep_val,
                        evidence_kind="FASTAPI_ROUTE_DEPENDENCY",
                        confidence=Confidence.HIGH,
                        details=f"Route-level dependency: {dep_val}",
                    )
                )

        # 3. Decorator Guards (Flask / Django / FastAPI)
        for dec in func.decorators:
            dname = dec.name.lower()
            if any(guard in dname for guard in KNOWN_AUTH_GUARDS):
                evidences.append(
                    AuthenticationEvidence(
                        mechanism_type=AuthMechanismType.DECORATOR,
                        source_location=dec.location,
                        endpoint=func.name,
                        guard_name=dec.name,
                        evidence_kind="AUTH_DECORATOR",
                        confidence=Confidence.HIGH,
                        details=f"Authentication decorator @{dec.name}",
                    )
                )

        # 4. AST Body Checks (Inline guards / helpers)
        if raw_ast_node:
            body_evs = cls._inspect_body_for_auth(raw_ast_node, func.name)
            evidences.extend(body_evs)

        return evidences

    @classmethod
    def _inspect_body_for_auth(
        cls,
        func_node: ast.AST,
        endpoint_name: str,
    ) -> list[AuthenticationEvidence]:
        """Scan function AST body for inline authentication patterns."""
        evidences: list[AuthenticationEvidence] = []

        for node in ast.walk(func_node):
            # Check function calls
            if isinstance(node, ast.Call):
                call_id = cls._get_call_name(node)
                if call_id and any(guard == call_id.lower() for guard in KNOWN_AUTH_GUARDS):
                    evidences.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.KNOWN_AUTH_HELPER,
                            source_location=SourceLocation.from_node(node),
                            endpoint=endpoint_name,
                            guard_name=call_id,
                            evidence_kind="INLINE_AUTH_HELPER_CALL",
                            confidence=Confidence.HIGH,
                            details=f"Inline auth helper invocation: {call_id}()",
                        )
                    )

            # Check if condition for user.is_authenticated
            if isinstance(node, ast.If):
                test_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                if "is_authenticated" in test_str:
                    evidences.append(
                        AuthenticationEvidence(
                            mechanism_type=AuthMechanismType.GUARD_CALL,
                            source_location=SourceLocation.from_node(node),
                            endpoint=endpoint_name,
                            guard_name="is_authenticated",
                            evidence_kind="INLINE_AUTHENTICATED_CHECK",
                            confidence=Confidence.HIGH,
                            details=f"Inline authentication condition: {test_str}",
                        )
                    )

        return evidences

    @classmethod
    def _collect_authz_evidence(
        cls,
        context: PythonASTContext,
        func: FunctionDefinition,
        framework: WebFramework,
        route_decorator: Decorator | None,
        raw_ast_node: ast.AST | None,
    ) -> list[AuthorizationEvidence]:
        """Extract observable evidence of authorization checks on an endpoint."""
        evidences: list[AuthorizationEvidence] = []

        # 1. Decorator Guards (Flask / Django / FastAPI)
        for dec in func.decorators:
            dname = dec.name.lower()
            dexpr = dec.expression.lower()
            if any(guard in dname or guard in dexpr for guard in KNOWN_AUTHZ_GUARDS):
                role_arg = dec.arguments[0] if dec.arguments else None
                evidences.append(
                    AuthorizationEvidence(
                        mechanism_type=AuthzMechanismType.AUTHORIZATION_DECORATOR,
                        source_location=dec.location,
                        endpoint=func.name,
                        role_or_permission=role_arg,
                        evidence_kind="AUTHZ_DECORATOR",
                        confidence=Confidence.HIGH,
                        details=f"Authorization decorator @{dec.name}",
                    )
                )

        # 2. Parameter Dependencies with scopes or role checks (FastAPI)
        for param in func.parameters:
            default_val = param.default_value or ""
            def_lower = default_val.lower()
            if "security(" in def_lower and "scopes=" in def_lower:
                evidences.append(
                    AuthorizationEvidence(
                        mechanism_type=AuthzMechanismType.PERMISSION_CHECK,
                        source_location=param.location or func.location,
                        endpoint=func.name,
                        role_or_permission="Security.scopes",
                        evidence_kind="FASTAPI_SECURITY_SCOPES",
                        confidence=Confidence.HIGH,
                        details=f"FastAPI Security scopes: {default_val}",
                    )
                )
            elif ("depends(" in def_lower or "security(" in def_lower) and (
                any(guard in def_lower for guard in KNOWN_AUTHZ_GUARDS)
                or any(term in def_lower for term in ("admin", "role", "perm", "authz", "superuser", "staff"))
            ):
                evidences.append(
                    AuthorizationEvidence(
                        mechanism_type=AuthzMechanismType.AUTHORIZATION_HELPER,
                        source_location=param.location or func.location,
                        endpoint=func.name,
                        role_or_permission=default_val,
                        evidence_kind="FASTAPI_AUTHZ_DEPENDENCY",
                        confidence=Confidence.HIGH,
                        details=f"Authorization dependency: {default_val}",
                    )
                )

        # 3. AST Body Checks (Role checks, permission checks, ownership checks)
        if raw_ast_node:
            body_authz = cls._inspect_body_for_authz(raw_ast_node, func.name)
            evidences.extend(body_authz)

        return evidences

    @classmethod
    def _inspect_body_for_authz(
        cls,
        func_node: ast.AST,
        endpoint_name: str,
    ) -> list[AuthorizationEvidence]:
        """Scan function AST body for inline authorization checks."""
        evidences: list[AuthorizationEvidence] = []

        for node in ast.walk(func_node):
            # Check If conditions: e.g. user.role != "admin", user.is_superuser
            if isinstance(node, ast.If):
                test_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                test_lower = test_str.lower()

                # Role check
                if any(
                    k in test_lower for k in ("role", "is_superuser", "is_admin", "is_staff")
                ):
                    evidences.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.ROLE_CHECK,
                            source_location=SourceLocation.from_node(node),
                            endpoint=endpoint_name,
                            role_or_permission=test_str,
                            evidence_kind="INLINE_ROLE_CHECK",
                            confidence=Confidence.HIGH,
                            details=f"Inline role check condition: {test_str}",
                        )
                    )

                # Permission check
                if any(k in test_lower for k in ("has_perm", "has_permission", "can_")):
                    evidences.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.PERMISSION_CHECK,
                            source_location=SourceLocation.from_node(node),
                            endpoint=endpoint_name,
                            role_or_permission=test_str,
                            evidence_kind="INLINE_PERMISSION_CHECK",
                            confidence=Confidence.HIGH,
                            details=f"Inline permission check: {test_str}",
                        )
                    )

                # Ownership check
                if (
                    "owner_id" in test_lower
                    or "user_id" in test_lower
                    or "creator_id" in test_lower
                ):
                    evidences.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.OWNERSHIP_CHECK,
                            source_location=SourceLocation.from_node(node),
                            endpoint=endpoint_name,
                            role_or_permission="resource_ownership",
                            evidence_kind="INLINE_OWNERSHIP_CHECK",
                            confidence=Confidence.MEDIUM,
                            details=f"Inline ownership check: {test_str}",
                        )
                    )

            # Check calls to check_permission or require_role
            if isinstance(node, ast.Call):
                call_id = cls._get_call_name(node)
                if call_id and any(guard in call_id.lower() for guard in KNOWN_AUTHZ_GUARDS):
                    evidences.append(
                        AuthorizationEvidence(
                            mechanism_type=AuthzMechanismType.AUTHORIZATION_HELPER,
                            source_location=SourceLocation.from_node(node),
                            endpoint=endpoint_name,
                            role_or_permission=call_id,
                            evidence_kind="AUTHZ_HELPER_CALL",
                            confidence=Confidence.HIGH,
                            details=f"Authorization helper invocation: {call_id}()",
                        )
                    )

        return evidences

    @classmethod
    def _assign_route_groups(cls, file_path: str, endpoints: list[EndpointDefinition]) -> None:
        """Assign cohesion route groups for consistency comparison."""
        file_stem = Path(file_path).stem
        for ep in endpoints:
            if ep.enclosing_class:
                ep.route_group = f"{file_stem}::{ep.enclosing_class}"
                continue

            # Check if decorated on a specific blueprint / router (e.g. bp.route, user_router.get)
            caller = ""
            if ep.function_def and ep.function_def.decorators:
                for dec in ep.function_def.decorators:
                    if "." in dec.name:
                        first_part = dec.name.split(".")[0].lower()
                        if first_part not in ("app", "api", "router", "v1_router", "api_router", "default_router"):
                            caller = first_part
                            break

            if caller:
                ep.route_group = f"{file_stem}::{caller}"
            elif ep.route_path:
                # Group by leading segment: e.g. /api/v1/users -> api/v1/users or /admin -> admin
                parts = [p for p in ep.route_path.strip("/").split("/") if p]
                if len(parts) >= 2 and parts[0] == "api":
                    ep.route_group = "/".join(parts[:3])
                elif parts:
                    ep.route_group = parts[0]
                else:
                    ep.route_group = file_stem
            else:
                ep.route_group = file_stem

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """Extract clean callable name from AST Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
