"""Production static analysis rules for Error Handling Debt."""

from __future__ import annotations

import ast

from app.analyzers.context import PythonASTContext
from app.analyzers.rules.base import BaseRule
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

LOGGING_CALL_NAMES = {
    "error",
    "exception",
    "warning",
    "warn",
    "critical",
    "fatal",
    "info",
    "debug",
    "log",
    "print",
    "print_exc",
    "print_stack",
    "format_exc",
    "capture_exception",
    "capture_message",
}

LOGGING_MODULE_PREFIXES = {
    "logger",
    "logging",
    "log",
    "sentry",
    "sentry_sdk",
    "traceback",
    "sys.stderr",
}


def _resolve_symbol(py_ctx: PythonASTContext, line: int) -> str:
    """Resolve qualified function, method, class, or module symbol for a line."""
    func = py_ctx.get_enclosing_function(line)
    if func:
        return func.qualified_name
    cls = py_ctx.get_enclosing_class(line)
    if cls:
        return cls.qualified_name
    return "<module>"


def _is_empty_body(body: list[ast.stmt]) -> tuple[bool, str]:
    """Determine if a block of statements is effectively empty."""
    if len(body) == 0:
        return True, "empty"
    non_trivial = []
    for stmt in body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            if stmt.value.value is Ellipsis or isinstance(stmt.value.value, str):
                continue
        non_trivial.append(stmt)
    if len(non_trivial) == 0:
        first = body[0]
        if isinstance(first, ast.Pass):
            return True, "pass"
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if first.value.value is Ellipsis:
                return True, "ellipsis"
            if isinstance(first.value.value, str):
                return True, "docstring"
        return True, "empty"
    return False, "non_empty"


def _calls_logging_or_error_reporting(node: ast.AST) -> bool:
    """Check if AST subtree invokes logging, printing, or error reporting."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            # Check attribute calls like logger.exception(...) or logging.error(...)
            if isinstance(child.func, ast.Attribute):
                attr_name = child.func.attr.lower()
                if attr_name in LOGGING_CALL_NAMES:
                    return True
                # Check receiver name
                receiver = ast.unparse(child.func.value).lower()
                if any(receiver.startswith(prefix) for prefix in LOGGING_MODULE_PREFIXES):
                    return True
            # Check standalone calls like print(...) or log(...)
            elif isinstance(child.func, ast.Name):
                func_name = child.func.id.lower()
                if func_name in LOGGING_CALL_NAMES:
                    return True
                if any(term in func_name for term in ("log", "report", "handle_error", "notify", "panic")):
                    return True
    return False


def _contains_raise_statement(node: ast.AST) -> bool:
    """Check if AST subtree contains a raise statement."""
    return any(isinstance(child, ast.Raise) for child in ast.walk(node))


def _contains_return_statement(node: ast.AST) -> bool:
    """Check if AST subtree contains a return statement."""
    return any(isinstance(child, ast.Return) for child in ast.walk(node))


# =============================================================================
# Rule 1: ENT-ERR-001 Bare Except Clause
# =============================================================================

class BareExceptRule(BaseRule):
    """Detects bare 'except:' clauses that catch all exceptions indiscriminately."""

    @property
    def rule_id(self) -> str:
        return "ENT-ERR-001"

    @property
    def name(self) -> str:
        return "Bare Except Clause"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.ERROR_HANDLING

    @property
    def description(self) -> str:
        return (
            "An exception handler uses a bare 'except:' clause without an explicit exception type, "
            "catching all exceptions including system signals."
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
            "A bare except catches BaseException subclasses including KeyboardInterrupt and SystemExit, "
            "obscuring system signals, preventing graceful process termination, and masking unrelated bugs."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Replace the bare 'except:' with the specific exception classes anticipated to fail during this operation "
            "(e.g. 'except ValueError:') or at minimum 'except Exception:'."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        findings: list[Finding] = []
        if not context.is_valid or context.ast_root is None:
            return findings

        for node in ast.walk(context.ast_root):
            if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                for handler in node.handlers:
                    if handler.type is None:
                        line_start = handler.lineno
                        line_end = handler.end_lineno or line_start
                        col_start = handler.col_offset
                        col_end = handler.end_col_offset
                        symbol = _resolve_symbol(context, line_start)
                        evidence = context.extract_snippet(line_start, min(line_end, line_start + 4))

                        fid = Finding.generate_deterministic_id(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            line_start=line_start,
                            line_end=line_end,
                            symbol=symbol,
                            evidence_signature="bare_except",
                        )
                        fingerprint = Finding.generate_fingerprint(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            symbol=symbol,
                            pattern_signature="bare_except",
                        )

                        findings.append(
                            Finding(
                                id=fid,
                                category=self.category,
                                rule_id=self.rule_id,
                                severity=self.default_severity,
                                confidence=self.default_confidence,
                                file=context.file_path,
                                line_start=line_start,
                                line_end=line_end,
                                column_start=col_start,
                                column_end=col_end,
                                symbol=symbol,
                                title=self.name,
                                description=(
                                    f"Exception handler at line {line_start} uses a bare 'except:' clause, "
                                    f"catching all exceptions indiscriminately."
                                ),
                                evidence=evidence,
                                impact=self.impact,
                                recommendation=self.recommendation,
                                fingerprint=fingerprint,
                                metadata={"is_bare": True, "exception_type": None},
                            )
                        )
        return findings


# =============================================================================
# Rule 2: ENT-ERR-002 Broad Exception Handler
# =============================================================================

class BroadExceptionHandlerRule(BaseRule):
    """Detects handlers catching broad exception types like Exception or BaseException."""

    @property
    def rule_id(self) -> str:
        return "ENT-ERR-002"

    @property
    def name(self) -> str:
        return "Broad Exception Handler"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.ERROR_HANDLING

    @property
    def description(self) -> str:
        return (
            "An exception handler catches broad exception classes ('Exception' or 'BaseException') "
            "rather than specific anticipated error types."
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
            "Catching broad exceptions inadvertently intercepts programming bugs (e.g. NameError, "
            "TypeError, AttributeError) and security assertion failures, treating systemic errors as handled conditions."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Catch only the specific, anticipated exception classes (e.g., 'except (KeyError, ValueError):') "
            "required for this operation."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        findings: list[Finding] = []
        if not context.is_valid or context.ast_root is None:
            return findings

        for node in ast.walk(context.ast_root):
            if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                for handler in node.handlers:
                    if handler.type is None:
                        continue

                    broad_match: str | None = None
                    if isinstance(handler.type, ast.Name) and handler.type.id in ("Exception", "BaseException"):
                        broad_match = handler.type.id
                    elif isinstance(handler.type, ast.Tuple):
                        for elt in handler.type.elts:
                            if isinstance(elt, ast.Name) and elt.id in ("Exception", "BaseException"):
                                broad_match = elt.id
                                break
                    elif isinstance(handler.type, ast.Attribute) and handler.type.attr in ("Exception", "BaseException"):
                        broad_match = handler.type.attr

                    if broad_match:
                        line_start = handler.lineno
                        line_end = handler.end_lineno or line_start
                        col_start = handler.col_offset
                        col_end = handler.end_col_offset
                        symbol = _resolve_symbol(context, line_start)
                        evidence = context.extract_snippet(line_start, min(line_end, line_start + 4))

                        fid = Finding.generate_deterministic_id(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            line_start=line_start,
                            line_end=line_end,
                            symbol=symbol,
                            evidence_signature=f"broad_{broad_match}",
                        )
                        fingerprint = Finding.generate_fingerprint(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            symbol=symbol,
                            pattern_signature=f"broad_{broad_match}",
                        )

                        findings.append(
                            Finding(
                                id=fid,
                                category=self.category,
                                rule_id=self.rule_id,
                                severity=self.default_severity,
                                confidence=self.default_confidence,
                                file=context.file_path,
                                line_start=line_start,
                                line_end=line_end,
                                column_start=col_start,
                                column_end=col_end,
                                symbol=symbol,
                                title=self.name,
                                description=(
                                    f"Exception handler at line {line_start} catches broad '{broad_match}' "
                                    f"rather than specific expected exception classes."
                                ),
                                evidence=evidence,
                                impact=self.impact,
                                recommendation=self.recommendation,
                                fingerprint=fingerprint,
                                metadata={"exception_type": broad_match},
                            )
                        )
        return findings


# =============================================================================
# Rule 3: ENT-ERR-003 Empty Exception Handler
# =============================================================================

class EmptyExceptionHandlerRule(BaseRule):
    """Detects exception handlers whose effective body is empty or does nothing."""

    @property
    def rule_id(self) -> str:
        return "ENT-ERR-003"

    @property
    def name(self) -> str:
        return "Empty Exception Handler"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.ERROR_HANDLING

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def description(self) -> str:
        return (
            "An exception handler has an empty body ('pass' or Ellipsis) that discards errors without handling or logging."
        )

    @property
    def impact(self) -> str:
        return (
            "Discarding caught exceptions without handling, logging, or propagating makes failures silent "
            "and invisible to telemetry, concealing root causes of operational defects."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Log the error with contextual information, perform explicit recovery, or document why the error is "
            "safely ignorable and re-raise if unrecoverable."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        findings: list[Finding] = []
        if not context.is_valid or context.ast_root is None:
            return findings

        for node in ast.walk(context.ast_root):
            if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                for handler in node.handlers:
                    is_empty, empty_type = _is_empty_body(handler.body)
                    if is_empty:
                        line_start = handler.lineno
                        line_end = handler.end_lineno or line_start
                        col_start = handler.col_offset
                        col_end = handler.end_col_offset
                        symbol = _resolve_symbol(context, line_start)
                        evidence = context.extract_snippet(line_start, line_end)

                        fid = Finding.generate_deterministic_id(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            line_start=line_start,
                            line_end=line_end,
                            symbol=symbol,
                            evidence_signature=f"empty_{empty_type}",
                        )
                        fingerprint = Finding.generate_fingerprint(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            symbol=symbol,
                            pattern_signature=f"empty_{empty_type}",
                        )

                        findings.append(
                            Finding(
                                id=fid,
                                category=self.category,
                                rule_id=self.rule_id,
                                severity=self.default_severity,
                                confidence=self.default_confidence,
                                file=context.file_path,
                                line_start=line_start,
                                line_end=line_end,
                                column_start=col_start,
                                column_end=col_end,
                                symbol=symbol,
                                title=self.name,
                                description=(
                                    f"Exception handler at line {line_start} has an empty body ({empty_type}) "
                                    f"that discards errors without handling or logging."
                                ),
                                evidence=evidence,
                                impact=self.impact,
                                recommendation=self.recommendation,
                                fingerprint=fingerprint,
                                metadata={"empty_statement_type": empty_type, "statement_count": len(handler.body)},
                            )
                        )
        return findings


# =============================================================================
# Rule 4: ENT-ERR-004 Silently Swallowed Exception
# =============================================================================

class SilentlySwallowedExceptionRule(BaseRule):
    """Detects non-empty exception handlers that silently swallow exceptions without logging or re-raising."""

    @property
    def rule_id(self) -> str:
        return "ENT-ERR-004"

    @property
    def name(self) -> str:
        return "Silently Swallowed Exception"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.ERROR_HANDLING

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def description(self) -> str:
        return (
            "An exception handler executes non-empty statements but fails to re-raise, return an error status, "
            "or emit diagnostic logging, silently suppressing the failure."
        )

    @property
    def impact(self) -> str:
        return (
            "Absorbing exceptions without error telemetry or propagation obscures systemic failures and causes "
            "silent state corruption in downstream components."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Record the exception with a logger (e.g. logger.exception) or propagate it to an outer error boundary."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        findings: list[Finding] = []
        if not context.is_valid or context.ast_root is None:
            return findings

        for node in ast.walk(context.ast_root):
            if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                for handler in node.handlers:
                    is_empty, _ = _is_empty_body(handler.body)
                    # Suppressed if empty handler rule (ENT-ERR-003) handles it
                    if is_empty:
                        continue

                    # Conservative check: if body raises, returns, or logs, it is NOT silently swallowed
                    if _contains_raise_statement(handler):
                        continue
                    if _contains_return_statement(handler):
                        continue
                    if _calls_logging_or_error_reporting(handler):
                        continue

                    line_start = handler.lineno
                    line_end = handler.end_lineno or line_start
                    col_start = handler.col_offset
                    col_end = handler.end_col_offset
                    symbol = _resolve_symbol(context, line_start)
                    evidence = context.extract_snippet(line_start, min(line_end, line_start + 5))

                    fid = Finding.generate_deterministic_id(
                        rule_id=self.rule_id,
                        file=context.file_path,
                        line_start=line_start,
                        line_end=line_end,
                        symbol=symbol,
                        evidence_signature="swallowed_body",
                    )
                    fingerprint = Finding.generate_fingerprint(
                        rule_id=self.rule_id,
                        file=context.file_path,
                        symbol=symbol,
                        pattern_signature="swallowed_body",
                    )

                    findings.append(
                        Finding(
                            id=fid,
                            category=self.category,
                            rule_id=self.rule_id,
                            severity=self.default_severity,
                            confidence=self.default_confidence,
                            file=context.file_path,
                            line_start=line_start,
                            line_end=line_end,
                            column_start=col_start,
                            column_end=col_end,
                            symbol=symbol,
                            title=self.name,
                            description=(
                                f"Exception handler at line {line_start} suppresses caught exceptions without "
                                f"logging, re-raising, or returning an error status."
                            ),
                            evidence=evidence,
                            impact=self.impact,
                            recommendation=self.recommendation,
                            fingerprint=fingerprint,
                            metadata={"statement_count": len(handler.body)},
                        )
                    )
        return findings


# =============================================================================
# Rule 5: ENT-ERR-005 Generic Fallback Return After Exception
# =============================================================================

class GenericFallbackReturnRule(BaseRule):
    """Detects exception handlers returning generic literal fallback values."""

    @property
    def rule_id(self) -> str:
        return "ENT-ERR-005"

    @property
    def name(self) -> str:
        return "Generic Fallback Return After Exception"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.ERROR_HANDLING

    @property
    def default_severity(self) -> Severity:
        return Severity.LOW

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.MEDIUM

    @property
    def description(self) -> str:
        return (
            "An exception handler catches an error and immediately returns a generic literal fallback value "
            "(e.g. None, False, empty list/dict) that conceals failure semantics."
        )

    @property
    def impact(self) -> str:
        return (
            "Returning generic falsy or empty literals on error conceals failure semantics, making it difficult "
            "for callers to distinguish between valid empty states and critical failures."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Distinguish failure states from valid results using domain-specific exceptions, optional Result types, "
            "or explicit error logging before fallback."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        findings: list[Finding] = []
        if not context.is_valid or context.ast_root is None:
            return findings

        for node in ast.walk(context.ast_root):
            if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                for handler in node.handlers:
                    for stmt in handler.body:
                        if isinstance(stmt, ast.Return) and stmt.value is not None:
                            val = stmt.value
                            is_generic_literal = False
                            fallback_type = "literal"

                            if isinstance(val, ast.Constant):
                                if val.value is None:
                                    is_generic_literal = True
                                    fallback_type = "None"
                                elif val.value is False:
                                    is_generic_literal = True
                                    fallback_type = "False"
                                elif val.value is True:
                                    is_generic_literal = True
                                    fallback_type = "True"
                                elif val.value == "":
                                    is_generic_literal = True
                                    fallback_type = "empty_string"
                            elif isinstance(val, ast.Dict) and len(val.keys) == 0:
                                is_generic_literal = True
                                fallback_type = "empty_dict"
                            elif isinstance(val, ast.List) and len(val.elts) == 0:
                                is_generic_literal = True
                                fallback_type = "empty_list"

                            if is_generic_literal:
                                line_start = stmt.lineno
                                line_end = stmt.end_lineno or line_start
                                col_start = stmt.col_offset
                                col_end = stmt.end_col_offset
                                symbol = _resolve_symbol(context, line_start)
                                evidence = context.extract_snippet(handler.lineno, min(line_end, handler.lineno + 4))

                                fid = Finding.generate_deterministic_id(
                                    rule_id=self.rule_id,
                                    file=context.file_path,
                                    line_start=line_start,
                                    line_end=line_end,
                                    symbol=symbol,
                                    evidence_signature=f"fallback_{fallback_type}",
                                )
                                fingerprint = Finding.generate_fingerprint(
                                    rule_id=self.rule_id,
                                    file=context.file_path,
                                    symbol=symbol,
                                    pattern_signature=f"fallback_{fallback_type}",
                                )

                                findings.append(
                                    Finding(
                                        id=fid,
                                        category=self.category,
                                        rule_id=self.rule_id,
                                        severity=self.default_severity,
                                        confidence=self.default_confidence,
                                        file=context.file_path,
                                        line_start=line_start,
                                        line_end=line_end,
                                        column_start=col_start,
                                        column_end=col_end,
                                        symbol=symbol,
                                        title=self.name,
                                        description=(
                                            f"Exception handler returns generic literal fallback '{fallback_type}' "
                                            f"on line {line_start} instead of structured error propagation."
                                        ),
                                        evidence=evidence,
                                        impact=self.impact,
                                        recommendation=self.recommendation,
                                        fingerprint=fingerprint,
                                        metadata={"fallback_type": fallback_type},
                                    )
                                )
        return findings


# =============================================================================
# Rule 6: ENT-ERR-006 Inconsistent Exception Handling Across Call Sites (DEFERRED)
# =============================================================================

RULE_ERR_006_DEFERRED = RuleDefinition(
    rule_id="ENT-ERR-006",
    category=DebtCategory.ERROR_HANDLING,
    title="Inconsistent Exception Handling Across Call Sites",
    description=(
        "Repeated invocations of the same library API or service function handle failure inconsistently "
        "across different files or modules."
    ),
    default_severity=Severity.LOW,
    default_confidence=Confidence.LOW,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Inconsistent error-handling policies across call sites create unpredictable failure modes when dependencies degrade."
    ),
    recommendation_template=(
        "Standardize call-site exception handling using a unified adapter, middleware, or repository-wide error policy."
    ),
    rationale=(
        "DEFERRED: Cross-file call consistency requires cross-module type inference and call graph resolution "
        "to avoid high false-positive rates on common library names. Explicitly deferred to future phases."
    ),
)
