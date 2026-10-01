"""Error Handling Debt Analyzer orchestrating Phase 3 error-handling rules."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.analyzers.rules.base import BaseRule
from app.analyzers.rules.error_handling.rules import (
    RULE_ERR_006_DEFERRED,
    BareExceptRule,
    BroadExceptionHandlerRule,
    EmptyExceptionHandlerRule,
    GenericFallbackReturnRule,
    SilentlySwallowedExceptionRule,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers.error_handling")


class ErrorHandlingDebtAnalyzer(BaseAnalyzer):
    """Analyzer detecting Error Handling Debt in source code.

    Enforces deterministic AST checks for:
    - ENT-ERR-001: Bare except clauses
    - ENT-ERR-002: Broad Exception handlers
    - ENT-ERR-003: Empty exception handlers
    - ENT-ERR-004: Silently swallowed exceptions
    - ENT-ERR-005: Generic fallback return after exception
    """

    def __init__(self, rules: Sequence[BaseRule] | None = None) -> None:
        if rules is not None:
            self._rules = list(rules)
        else:
            self._rules = [
                BareExceptRule(),
                BroadExceptionHandlerRule(),
                EmptyExceptionHandlerRule(),
                SilentlySwallowedExceptionRule(),
                GenericFallbackReturnRule(),
            ]

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
        rule_defs = [r.definition for r in self._rules]
        # Include deferred rule in registry definitions so clients can inspect full taxonomy
        rule_defs.append(RULE_ERR_006_DEFERRED)
        return rule_defs

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute deterministic AST visitor analysis across all valid Python files in context."""
        raw_findings: list[Finding] = []
        valid_python_contexts = context.get_valid_python_contexts()

        for py_ctx in valid_python_contexts:
            file_findings: list[Finding] = []
            for rule in self._rules:
                try:
                    results = rule.analyze_file(py_ctx)
                    file_findings.extend(results)
                except Exception as exc:
                    logger.warning(
                        "Rule %s failed while analyzing '%s': %s",
                        rule.rule_id,
                        py_ctx.file_path,
                        exc,
                    )

            # File-level suppression & deduplication
            filtered_findings = self._deduplicate_and_suppress(file_findings)
            raw_findings.extend(filtered_findings)

        # Deterministic global sorting: (file, line_start, rule_id)
        return sorted(
            raw_findings,
            key=lambda f: (f.file, f.line_start, f.rule_id, f.id),
        )

    def _deduplicate_and_suppress(self, findings: list[Finding]) -> list[Finding]:
        """Apply suppression and deduplication policies.

        Suppression Policy:
        - If an empty handler (ENT-ERR-003) is detected at a line, suppress ENT-ERR-004
          (Silently Swallowed) for that same handler to avoid redundant noise.
        - Deduplicate identical (file, line_start, rule_id) candidates.
        """
        # Collect line numbers where ENT-ERR-003 triggered
        empty_handler_lines = {
            f.line_start for f in findings if f.rule_id == "ENT-ERR-003"
        }

        unique_map: dict[tuple[str, int, str], Finding] = {}
        for f in findings:
            # Suppress ENT-ERR-004 if ENT-ERR-003 already flagged the handler as empty
            if f.rule_id == "ENT-ERR-004" and f.line_start in empty_handler_lines:
                continue

            key = (f.file, f.line_start, f.rule_id)
            if key not in unique_map:
                unique_map[key] = f

        return list(unique_map.values())
