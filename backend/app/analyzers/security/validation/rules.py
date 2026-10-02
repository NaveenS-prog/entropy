"""Rule definitions and implementations for Input Validation Debt Analyzer."""

from __future__ import annotations

import ast
import re

from app.analyzers.context import PythonASTContext
from app.analyzers.rules.base import BaseRule
from app.analyzers.security.frameworks import FrameworkRouteDetector
from app.analyzers.security.models import EndpointDefinition, WebFramework
from app.analyzers.security.validation.models import (
    EndpointInputProfile,
    InputSourceType,
    InputValidationEvidence,
    ValidationMechanismType,
)
from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import Finding
from app.parser.python.models import SourceLocation

# Keywords indicating schema or structured model names
KNOWN_SCHEMA_SUFFIXES = (
    "schema",
    "create",
    "update",
    "request",
    "payload",
    "dto",
    "model",
    "input",
    "form",
    "serializer",
)

# Common framework dependencies that should not be treated as external input
FRAMEWORK_DEPENDENCY_TYPES = {
    "request",
    "response",
    "session",
    "db",
    "dbsession",
    "backgroundtasks",
    "background_tasks",
    "security",
    "user",
    "current_user",
    "client",
}

# SQL keyword patterns for sink detection
SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|UNION\s+SELECT)\b",
    re.IGNORECASE,
)

# Sensitive route keywords
SENSITIVE_INPUT_KEYWORDS = {
    "user",
    "users",
    "account",
    "accounts",
    "admin",
    "payment",
    "payments",
    "billing",
    "order",
    "orders",
    "create",
    "update",
    "edit",
    "delete",
    "upload",
    "import",
    "config",
    "settings",
    "auth",
    "register",
    "signup",
    "token",
}


def _extract_input_profile(
    context: PythonASTContext,
    endpoint: EndpointDefinition,
    ast_func_map: dict[tuple[str, int], ast.AST],
) -> EndpointInputProfile:
    """Analyze an endpoint AST node to extract its input sources, validation mechanisms, and sinks."""
    ast_node = ast_func_map.get((endpoint.symbol, endpoint.location.line_start))

    input_sources: list[InputSourceType] = []
    validation_mechanisms: list[ValidationMechanismType] = []
    unvalidated_evidence: list[InputValidationEvidence] = []
    sink_evidence: list[InputValidationEvidence] = []
    has_schema = False
    has_unvalidated = False

    # Check HTTP methods and path sensitivity
    is_state_mutating = any(m in ("POST", "PUT", "PATCH", "DELETE") for m in endpoint.http_methods)
    route_str = (endpoint.route_path or "").lower()
    symbol_str = endpoint.symbol.lower()
    is_sensitive = (
        is_state_mutating
        or any(k in route_str for k in SENSITIVE_INPUT_KEYWORDS)
        or any(k in symbol_str for k in SENSITIVE_INPUT_KEYWORDS)
    )

    if not ast_node or not isinstance(ast_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return EndpointInputProfile(
            endpoint_symbol=endpoint.symbol,
            route_path=endpoint.route_path,
            http_methods=endpoint.http_methods,
            route_group=endpoint.route_group,
            is_sensitive=is_sensitive,
            input_sources=input_sources,
            validation_mechanisms=validation_mechanisms,
            has_schema_validation=has_schema,
            has_unvalidated_input=has_unvalidated,
            unvalidated_evidence=unvalidated_evidence,
            sink_evidence=sink_evidence,
            metadata={},
        )

    # 1. Parameter Inspection (FastAPI / Generic)
    input_vars: set[str] = set()

    for arg in ast_node.args.args:
        arg_name = arg.arg
        if arg_name in ("self", "cls"):
            continue

        type_annotation = ""
        if arg.annotation:
            type_annotation = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""

        norm_type = type_annotation.lower().strip()
        norm_arg = arg_name.lower().strip()

        # Check if parameter is a framework dependency
        if norm_type in FRAMEWORK_DEPENDENCY_TYPES or norm_arg in FRAMEWORK_DEPENDENCY_TYPES:
            continue

        # Check if default is a Dependency (Depends / Security)
        # Note: defaults list corresponds to the last N args
        arg_idx = ast_node.args.args.index(arg)
        num_defaults = len(ast_node.args.defaults)
        defaults_offset = len(ast_node.args.args) - num_defaults
        is_depends = False
        if arg_idx >= defaults_offset:
            default_node = ast_node.args.defaults[arg_idx - defaults_offset]
            default_str = ast.unparse(default_node).lower() if hasattr(ast, "unparse") else ""
            if "depends(" in default_str or "security(" in default_str:
                is_depends = True

        if is_depends:
            continue

        # Non-dependency parameters are external input candidates for sink tracing
        input_vars.add(arg_name)

        # Check for structured schema validation
        if any(norm_type.endswith(sfx) or sfx in norm_type for sfx in KNOWN_SCHEMA_SUFFIXES):
            has_schema = True
            validation_mechanisms.append(ValidationMechanismType.PYDANTIC_SCHEMA)
            continue

        # Scalar type constraints (int, float, bool, UUID)
        if norm_type in ("int", "float", "bool", "uuid"):
            validation_mechanisms.append(ValidationMechanismType.TYPE_CONSTRAINT)
            continue

        # Unvalidated external parameter in a sensitive or mutating route
        if is_sensitive and (
            norm_type in ("", "dict", "dict[str, any]", "any", "list", "list[any]")
            or not type_annotation
            or norm_arg in ("data", "payload", "body", "input_data", "params")
        ):
            input_sources.append(InputSourceType.FASTAPI_PARAM)
            unval_ev = InputValidationEvidence(
                source_location=SourceLocation.from_node(arg),
                endpoint=endpoint.symbol,
                input_source=InputSourceType.FASTAPI_PARAM,
                param_or_field_name=arg_name,
                validation_mechanism=ValidationMechanismType.NONE,
                confidence=Confidence.HIGH if norm_type in ("dict", "dict[str, any]") else Confidence.MEDIUM,
                details=f"Parameter '{arg_name}' on route '{endpoint.display_route}' lacks schema validation",
            )
            unvalidated_evidence.append(unval_ev)
            has_unvalidated = True

    # 2. Body Traversal for Request Access & Validation Checks
    has_explicit_check = False
    has_form_or_serializer = False

    for node in ast.walk(ast_node):
        # Explicit validation checks: isinstance, len(), custom validate_*, form.is_valid()
        if isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                call_name = node.func.attr

            call_str = ast.unparse(node.func).lower() if hasattr(ast, "unparse") else ""
            if call_name in ("is_valid", "validate", "load") or "serializer" in call_str:
                has_form_or_serializer = True
                validation_mechanisms.append(ValidationMechanismType.DRF_SERIALIZER)
            elif call_name.startswith("validate_") or call_name in ("isinstance", "len", "match", "search"):
                has_explicit_check = True
                validation_mechanisms.append(ValidationMechanismType.EXPLICIT_CHECK)

        # Flask / Django Request Object Access
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "request":
            attr = node.attr
            if attr in ("json", "get_json", "form", "values", "data"):
                src = (
                    InputSourceType.FLASK_REQUEST_JSON
                    if "json" in attr
                    else (
                        InputSourceType.DJANGO_REQUEST_DATA
                        if endpoint.framework == WebFramework.DJANGO
                        else InputSourceType.FLASK_REQUEST_FORM
                    )
                )
                input_sources.append(src)
                # Check enclosing assignment to record variable name
                # Walk will find targets in Assign
            elif attr in ("args", "GET", "query_params"):
                src = (
                    InputSourceType.DJANGO_REQUEST_GET
                    if attr == "GET"
                    else InputSourceType.FLASK_REQUEST_ARGS
                )
                input_sources.append(src)

        # Record assigned variables from request
        if isinstance(node, ast.Assign):
            val_str = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
            if "request." in val_str:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        input_vars.add(tgt.id)

    # If endpoint uses Flask/Django request data in a sensitive route without schema/serializer/explicit check
    if is_sensitive and (InputSourceType.FLASK_REQUEST_JSON in input_sources or InputSourceType.DJANGO_REQUEST_DATA in input_sources or InputSourceType.FLASK_REQUEST_FORM in input_sources):
        if not (has_form_or_serializer or has_explicit_check or has_schema):
            has_unvalidated = True
            unvalidated_evidence.append(
                InputValidationEvidence(
                    source_location=endpoint.location,
                    endpoint=endpoint.symbol,
                    input_source=input_sources[0],
                    param_or_field_name="request_payload",
                    validation_mechanism=ValidationMechanismType.NONE,
                    confidence=Confidence.HIGH,
                    details=f"Endpoint '{endpoint.display_route}' consumes raw request payload without schema or validation",
                )
            )

    # 3. Sink Detection (SQL injection, subprocess, path traversal, open redirect, eval)
    for node in ast.walk(ast_node):
        if not isinstance(node, ast.Call):
            continue

        call_expr = ast.unparse(node.func).lower() if hasattr(ast, "unparse") else ""

        # Check arguments for input variable usage
        for arg_idx, call_arg in enumerate(node.args):
            arg_str = ast.unparse(call_arg) if hasattr(ast, "unparse") else ""

            # Check if arg incorporates any of our untrusted input_vars
            uses_input = any(re.search(rf"\b{re.escape(iv)}\b", arg_str) for iv in input_vars)
            if not uses_input:
                continue

            # Sink A: SQL Query execution with string interpolation or concatenation
            if any(method in call_expr for method in ("execute", "raw", "select")) or "cursor" in call_expr:
                if isinstance(call_arg, ast.JoinedStr) or (isinstance(call_arg, ast.BinOp) and isinstance(call_arg.op, (ast.Add, ast.Mod))):
                    if SQL_KEYWORDS.search(arg_str):
                        sink_evidence.append(
                            InputValidationEvidence(
                                source_location=SourceLocation.from_node(call_arg),
                                endpoint=endpoint.symbol,
                                input_source=InputSourceType.FASTAPI_PARAM if endpoint.framework == WebFramework.FASTAPI else InputSourceType.FLASK_REQUEST_JSON,
                                param_or_field_name=arg_str,
                                validation_mechanism=ValidationMechanismType.NONE,
                                sink="sql_query",
                                confidence=Confidence.HIGH,
                                details=f"External input formatted directly into SQL query: {arg_str[:60]}",
                            )
                        )

            # Sink B: Subprocess execution with shell=True or unquoted command
            if any(sub in call_expr for sub in ("subprocess.run", "subprocess.popen", "os.system", "os.popen")):
                sink_evidence.append(
                    InputValidationEvidence(
                        source_location=SourceLocation.from_node(call_arg),
                        endpoint=endpoint.symbol,
                        input_source=InputSourceType.FASTAPI_PARAM if endpoint.framework == WebFramework.FASTAPI else InputSourceType.FLASK_REQUEST_ARGS,
                        param_or_field_name=arg_str,
                        validation_mechanism=ValidationMechanismType.NONE,
                        sink="subprocess",
                        confidence=Confidence.HIGH,
                        details=f"External input passed directly to command execution: {arg_str[:60]}",
                    )
                )

            # Sink C: Dynamic execution (eval, exec, pickle)
            if call_expr in ("eval", "exec", "pickle.loads", "yaml.load"):
                sink_evidence.append(
                    InputValidationEvidence(
                        source_location=SourceLocation.from_node(call_arg),
                        endpoint=endpoint.symbol,
                        input_source=InputSourceType.FASTAPI_PARAM if endpoint.framework == WebFramework.FASTAPI else InputSourceType.FLASK_REQUEST_JSON,
                        param_or_field_name=arg_str,
                        validation_mechanism=ValidationMechanismType.NONE,
                        sink="eval_exec",
                        confidence=Confidence.HIGH,
                        details=f"External input passed directly to dynamic evaluation API: {call_expr}",
                    )
                )

            # Sink D: Open redirect
            if "redirect" in call_expr and arg_idx == 0:
                if not has_explicit_check:
                    sink_evidence.append(
                        InputValidationEvidence(
                            source_location=SourceLocation.from_node(call_arg),
                            endpoint=endpoint.symbol,
                            input_source=InputSourceType.FASTAPI_PARAM if endpoint.framework == WebFramework.FASTAPI else InputSourceType.FLASK_REQUEST_ARGS,
                            param_or_field_name=arg_str,
                            validation_mechanism=ValidationMechanismType.NONE,
                            sink="redirect",
                            confidence=Confidence.MEDIUM,
                            details=f"External input passed directly to redirect without URL validation: {arg_str[:60]}",
                        )
                    )

    return EndpointInputProfile(
        endpoint_symbol=endpoint.symbol,
        route_path=endpoint.route_path,
        http_methods=endpoint.http_methods,
        route_group=endpoint.route_group,
        is_sensitive=is_sensitive,
        input_sources=input_sources,
        validation_mechanisms=validation_mechanisms,
        has_schema_validation=has_schema or has_form_or_serializer,
        has_unvalidated_input=has_unvalidated,
        unvalidated_evidence=unvalidated_evidence,
        sink_evidence=sink_evidence,
        metadata={},
    )


# =============================================================================
# Rule Implementations
# =============================================================================


class PotentiallyUnvalidatedExternalInputRule(BaseRule):
    """ENT-INPUT-001: Potentially Unvalidated External Input."""

    @property
    def rule_id(self) -> str:
        return "ENT-INPUT-001"

    @property
    def name(self) -> str:
        return "Potentially Unvalidated External Input"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.INPUT_VALIDATION

    @property
    def description(self) -> str:
        return (
            "Detects security-sensitive endpoints or state-mutating route handlers that directly "
            "consume external input without recognizable schema validation, type constraints, or checks."
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
            "Consuming raw, unvalidated external input exposes the application to data corruption, "
            "unexpected runtime exceptions, injection hazards, and business logic flaws."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Define explicit schema models (e.g. Pydantic BaseModel, DRF Serializers, or Django Forms) "
            "with field-level validation and type constraints for all incoming payloads."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        if not endpoints:
            return []

        ast_func_map: dict[tuple[str, int], ast.AST] = {}
        if context.ast_root:
            for node in ast.walk(context.ast_root):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    ast_func_map[(node.name, getattr(node, "lineno", 0))] = node

        findings: list[Finding] = []

        for ep in endpoints:
            profile = _extract_input_profile(context, ep, ast_func_map)
            if profile.is_sensitive and profile.has_unvalidated_input and not profile.has_schema_validation:
                for ev in profile.unvalidated_evidence:
                    snippet = context.extract_snippet(
                        ev.source_location.line_start,
                        ev.source_location.line_end,
                        context_before=1,
                        context_after=2,
                    )
                    sig = f"{ep.symbol}:{ev.param_or_field_name}:{ev.input_source.value}"
                    fid = Finding.generate_deterministic_id(
                        rule_id=self.rule_id,
                        file=context.file_path,
                        line_start=ev.source_location.line_start,
                        line_end=ev.source_location.line_end,
                        symbol=ep.symbol,
                        evidence_signature=sig,
                    )
                    fp = Finding.generate_fingerprint(
                        rule_id=self.rule_id,
                        file=context.file_path,
                        symbol=ep.symbol,
                        pattern_signature=sig,
                    )
                    finding = Finding(
                        id=fid,
                        fingerprint=fp,
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=self.default_severity,
                        confidence=ev.confidence,
                        file=context.file_path,
                        line_start=ev.source_location.line_start,
                        line_end=ev.source_location.line_end,
                        symbol=ep.symbol,
                        title=f"Unvalidated External Input in '{ep.display_route}'",
                        description=(
                            f"Endpoint '{ep.display_route}' accepts external input ({ev.param_or_field_name}) "
                            f"via {ev.input_source.value} without recognizable schema validation or constraints."
                        ),
                        evidence=snippet,
                        impact=self.impact,
                        recommendation=self.recommendation,
                    )
                    findings.append(finding)

        return findings


class InconsistentInputValidationRule(BaseRule):
    """ENT-INPUT-002: Inconsistent Input Validation."""

    @property
    def rule_id(self) -> str:
        return "ENT-INPUT-002"

    @property
    def name(self) -> str:
        return "Inconsistent Input Validation"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.INPUT_VALIDATION

    @property
    def description(self) -> str:
        return (
            "Detects structurally related endpoints within the same route group that handle comparable "
            "external input but utilize materially inconsistent validation strategies (e.g. schema vs raw dict)."
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
            "Inconsistent validation approaches across sibling endpoints lead to uneven data hygiene, "
            "validation bypasses, and high maintenance debt when updating shared entity schemas."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Standardize input validation across all endpoints in this route group by adopting uniform "
            "schema models or serializers."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        if len(endpoints) < 2:
            return []

        ast_func_map: dict[tuple[str, int], ast.AST] = {}
        if context.ast_root:
            for node in ast.walk(context.ast_root):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    ast_func_map[(node.name, getattr(node, "lineno", 0))] = node

        # Group endpoints by route_group
        groups: dict[str, list[tuple[EndpointDefinition, EndpointInputProfile]]] = {}
        for ep in endpoints:
            if not ep.route_group:
                continue
            profile = _extract_input_profile(context, ep, ast_func_map)
            # Only consider endpoints that receive input or mutate state
            if profile.input_sources or profile.has_schema_validation or profile.has_unvalidated_input:
                groups.setdefault(ep.route_group, []).append((ep, profile))

        findings: list[Finding] = []

        for group_name, members in groups.items():
            if len(members) < 2:
                continue

            schema_members = [m for m in members if m[1].has_schema_validation]
            unvalidated_members = [m for m in members if m[1].has_unvalidated_input and not m[1].has_schema_validation]

            # Inconsistency: at least one sibling uses schemas, while another uses raw unvalidated input
            if schema_members and unvalidated_members:
                schema_symbols = [m[0].symbol for m in schema_members]
                for unval_ep, _unval_profile in unvalidated_members:
                    snippet = context.extract_snippet(
                        unval_ep.location.line_start,
                        unval_ep.location.line_end,
                        context_before=1,
                        context_after=2,
                    )
                    desc = (
                        f"Endpoint '{unval_ep.display_route}' handles external input without schema validation, "
                        f"while sibling route(s) in group '{group_name}' ({', '.join(schema_symbols)}) "
                        f"enforce structured schema validation."
                    )
                    sig = f"{group_name}:{unval_ep.symbol}:inconsistent_schema"
                    fid = Finding.generate_deterministic_id(
                        rule_id=self.rule_id,
                        file=context.file_path,
                        line_start=unval_ep.location.line_start,
                        line_end=unval_ep.location.line_end,
                        symbol=unval_ep.symbol,
                        evidence_signature=sig,
                    )
                    fp = Finding.generate_fingerprint(
                        rule_id=self.rule_id,
                        file=context.file_path,
                        symbol=unval_ep.symbol,
                        pattern_signature=sig,
                    )
                    finding = Finding(
                        id=fid,
                        fingerprint=fp,
                        rule_id=self.rule_id,
                        category=self.category,
                        severity=self.default_severity,
                        confidence=self.default_confidence,
                        file=context.file_path,
                        line_start=unval_ep.location.line_start,
                        line_end=unval_ep.location.line_end,
                        symbol=unval_ep.symbol,
                        title=f"Inconsistent Input Validation in '{group_name}' Group",
                        description=desc,
                        evidence=snippet,
                        impact=self.impact,
                        recommendation=self.recommendation,
                    )
                    findings.append(finding)

        return findings


class UnsafeDirectInputUsageRule(BaseRule):
    """ENT-INPUT-003: Unsafe Direct Input Usage."""

    @property
    def rule_id(self) -> str:
        return "ENT-INPUT-003"

    @property
    def name(self) -> str:
        return "Unsafe Direct Input Usage"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.INPUT_VALIDATION

    @property
    def description(self) -> str:
        return (
            "Detects external input flowing directly into security-sensitive operations "
            "(SQL queries, command execution, filesystem access, redirects, or dynamic execution) "
            "without recognizable validation or sanitization."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Passing unsanitized external input to system execution or database sinks introduces "
            "critical architectural vulnerabilities such as SQL injection, command injection, or path traversal."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Never construct SQL queries or shell commands via string interpolation. Use parameterized "
            "database queries, safe subprocess argument lists without shell=True, and strict path allowlists."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        endpoints = FrameworkRouteDetector.extract_endpoints(context)
        if not endpoints:
            return []

        ast_func_map: dict[tuple[str, int], ast.AST] = {}
        if context.ast_root:
            for node in ast.walk(context.ast_root):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    ast_func_map[(node.name, getattr(node, "lineno", 0))] = node

        findings: list[Finding] = []

        for ep in endpoints:
            profile = _extract_input_profile(context, ep, ast_func_map)
            for sink_ev in profile.sink_evidence:
                snippet = context.extract_snippet(
                    sink_ev.source_location.line_start,
                    sink_ev.source_location.line_end,
                    context_before=1,
                    context_after=2,
                )
                severity = Severity.HIGH if sink_ev.sink in ("sql_query", "subprocess", "eval_exec") else Severity.MEDIUM

                sig = f"{ep.symbol}:{sink_ev.sink}:{sink_ev.source_location.line_start}"
                fid = Finding.generate_deterministic_id(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    line_start=sink_ev.source_location.line_start,
                    line_end=sink_ev.source_location.line_end,
                    symbol=ep.symbol,
                    evidence_signature=sig,
                )
                fp = Finding.generate_fingerprint(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    symbol=ep.symbol,
                    pattern_signature=sig,
                )
                finding = Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=severity,
                    confidence=sink_ev.confidence,
                    file=context.file_path,
                    line_start=sink_ev.source_location.line_start,
                    line_end=sink_ev.source_location.line_end,
                    symbol=ep.symbol,
                    title=f"Unsafe Direct Input Flow to {sink_ev.sink.upper()} in '{ep.display_route}'",
                    description=sink_ev.details,
                    evidence=snippet,
                    impact=self.impact,
                    recommendation=self.recommendation,
                )
                findings.append(finding)

        return findings
