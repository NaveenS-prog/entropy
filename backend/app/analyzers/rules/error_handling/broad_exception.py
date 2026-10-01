"""Broad Exception & Swallowed Error Handling Analyzer.

Identifies silent security debt resulting from broad, bare, or swallowed exception handlers
that obscure security-critical failures (such as auth tokens, crypto errors, or network I/O).
"""

import ast
from uuid import uuid4

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

RULE_ERR_001 = RuleDefinition(
    rule_id="ERR-001",
    category=DebtCategory.ERROR_HANDLING,
    title="Swallowed Exception in Error Handler",
    description=(
        "An exception handler catches an exception and silently discards it using 'pass' or "
        "an empty statement without logging or re-raising."
    ),
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Swallowing exceptions obscures internal failures, preventing security monitoring from "
        "detecting state corruption, invalid authorization tokens, or compromised data paths."
    ),
    recommendation_template=(
        "Log the exception with appropriate contextual severity, and handle or re-raise the error. "
        "Never discard exceptions silently in security-sensitive control flows."
    ),
    rationale=(
        "Generated code frequently inserts 'try...except: pass' to suppress runtime crashes during "
        "prototyping, accumulating silent risk."
    ),
)

RULE_ERR_002 = RuleDefinition(
    rule_id="ERR-002",
    category=DebtCategory.ERROR_HANDLING,
    title="Catching Overly Broad Exception Type",
    description=(
        "A bare 'except:' or broad 'except Exception:' clause catches all exceptions indiscriminately."
    ),
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Catching broad exceptions inadvertently catches programming bugs (e.g. NameError, "
        "TypeError) and unexpected security assertion failures, treating them as expected conditions."
    ),
    recommendation_template=(
        "Catch specific, expected exception classes (e.g. ValueError, KeyError, NetworkTimeout) "
        "rather than the root Exception class."
    ),
    rationale=(
        "Broad exception handlers create brittle architectures where unexpected failure modes go undetected."
    ),
)


class ErrorHandlingAstVisitor(ast.NodeVisitor):
    """AST visitor detecting broad and swallowed exception patterns."""

    def __init__(self, parsed_file: ParsedFile):
        self.parsed_file = parsed_file
        self.findings: list[Finding] = []
        self._current_scope: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._current_scope.append(node.name)
        self.generic_visit(node)
        self._current_scope.pop()

    def _get_symbol_name(self) -> str | None:
        return "::".join(self._current_scope) if self._current_scope else None

    def visit_Try(self, node: ast.Try) -> None:
        for handler in node.handlers:
            self._check_handler(handler)
        self.generic_visit(node)

    def _check_handler(self, handler: ast.ExceptHandler) -> None:
        is_bare = handler.type is None
        is_broad_exception = False

        if handler.type is not None:
            if isinstance(handler.type, ast.Name) and handler.type.id in ("Exception", "BaseException"):
                is_broad_exception = True

        # Check if swallowed (body is solely 'pass', '...', or docstring)
        is_swallowed = False
        if len(handler.body) == 1:
            stmt = handler.body[0]
            if isinstance(stmt, ast.Pass):
                is_swallowed = True
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                # Ellipsis or standalone string/literal
                is_swallowed = True

        symbol = self._get_symbol_name()
        line_start = handler.lineno
        line_end = handler.end_lineno or handler.lineno

        evidence = self.parsed_file.extract_snippet(line_start, line_end)

        if is_swallowed:
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_ERR_001.rule_id,
                file=self.parsed_file.relative_path,
                symbol=symbol,
                pattern_signature=f"swallowed_at_{line_start}",
            )
            self.findings.append(
                Finding(
                    id=str(uuid4()),
                    category=DebtCategory.ERROR_HANDLING,
                    rule_id=RULE_ERR_001.rule_id,
                    severity=RULE_ERR_001.default_severity,
                    confidence=RULE_ERR_001.default_confidence,
                    file=self.parsed_file.relative_path,
                    line_start=line_start,
                    line_end=line_end,
                    symbol=symbol,
                    title=RULE_ERR_001.title,
                    description=(
                        f"Exception handler at line {line_start} in '{self.parsed_file.relative_path}' "
                        f"silently swallows exceptions with an empty body."
                    ),
                    evidence=evidence,
                    impact=RULE_ERR_001.impact_template,
                    recommendation=RULE_ERR_001.recommendation_template,
                    fingerprint=fingerprint,
                    metadata={"handler_type": "bare" if is_bare else "typed", "swallowed": True},
                )
            )
        elif is_bare or is_broad_exception:
            broad_type = "bare 'except:'" if is_bare else "broad 'except Exception:'"
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_ERR_002.rule_id,
                file=self.parsed_file.relative_path,
                symbol=symbol,
                pattern_signature=f"broad_at_{line_start}",
            )
            self.findings.append(
                Finding(
                    id=str(uuid4()),
                    category=DebtCategory.ERROR_HANDLING,
                    rule_id=RULE_ERR_002.rule_id,
                    severity=RULE_ERR_002.default_severity,
                    confidence=RULE_ERR_002.default_confidence,
                    file=self.parsed_file.relative_path,
                    line_start=line_start,
                    line_end=line_end,
                    symbol=symbol,
                    title=RULE_ERR_002.title,
                    description=(
                        f"Exception handler at line {line_start} uses {broad_type} clause instead of "
                        f"catching specific failure types."
                    ),
                    evidence=evidence,
                    impact=RULE_ERR_002.impact_template,
                    recommendation=RULE_ERR_002.recommendation_template,
                    fingerprint=fingerprint,
                    metadata={"handler_type": broad_type, "swallowed": False},
                )
            )


class ErrorHandlingDebtAnalyzer(BaseAnalyzer):
    """Analyzer detecting Error Handling Debt in source code."""

    @property
    def analyzer_id(self) -> str:
        return "error_handling_debt_analyzer"

    @property
    def name(self) -> str:
        return "Error Handling Debt Analyzer"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.ERROR_HANDLING

    @property
    def supported_languages(self) -> set[SupportedLanguage]:
        return {SupportedLanguage.PYTHON}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_ERR_001, RULE_ERR_002]

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        python_files = context.get_files_for_language(SupportedLanguage.PYTHON)

        for parsed_file in python_files:
            if not parsed_file.is_valid or parsed_file.ast_root is None:
                continue

            visitor = ErrorHandlingAstVisitor(parsed_file)
            visitor.visit(parsed_file.ast_root)
            findings.extend(visitor.findings)

        return findings
