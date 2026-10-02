"""Input Validation Consistency Static Analyzer.

Evaluates Python web codebases for input validation consistency, schema coverage,
and direct flow into dangerous execution sinks.
"""

from __future__ import annotations

import logging

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.analyzers.rules.base import BaseRule
from app.analyzers.security.validation.rules import (
    InconsistentInputValidationRule,
    PotentiallyUnvalidatedExternalInputRule,
    UnsafeDirectInputUsageRule,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers.validation")


class InputValidationConsistencyAnalyzer(BaseAnalyzer):
    """Static analyzer for identifying input validation architectural debt."""

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        self._rule_instances: list[BaseRule] = rules or [
            PotentiallyUnvalidatedExternalInputRule(),
            InconsistentInputValidationRule(),
            UnsafeDirectInputUsageRule(),
        ]
        self._rules_meta: list[RuleDefinition] = [r.definition for r in self._rule_instances]

    @property
    def analyzer_id(self) -> str:
        return "input_validation_consistency_analyzer"

    @property
    def name(self) -> str:
        return "Input Validation Consistency Analyzer"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.INPUT_VALIDATION

    @property
    def supported_languages(self) -> set[SupportedLanguage]:
        return {SupportedLanguage.PYTHON}

    @property
    def rules(self) -> list[RuleDefinition]:
        return self._rules_meta

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute input validation rules across all Python files in the repository."""
        valid_python_contexts = context.get_valid_python_contexts()
        raw_findings: list[Finding] = []

        for py_context in valid_python_contexts:
            for rule in self._rule_instances:
                try:
                    file_findings = rule.analyze_file(py_context)
                    raw_findings.extend(file_findings)
                except Exception as e:
                    logger.error(
                        "Rule '%s' failed on file '%s': %s",
                        rule.rule_id,
                        py_context.file_path,
                        e,
                        exc_info=True,
                    )

        # Apply suppression and deduplication
        processed = self._suppress_and_deduplicate(raw_findings)
        return processed

    def _suppress_and_deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Apply suppression precedence:

        1. If an endpoint has ENT-INPUT-002 (Inconsistent Input Validation),
           suppress ENT-INPUT-001 (Potentially Unvalidated Endpoint) for that same endpoint.
        2. Deduplicate identical fingerprints.
        """
        # Collect symbols with ENT-INPUT-002
        inconsistent_endpoints: set[tuple[str, str]] = {
            (f.file, f.symbol) for f in findings if f.rule_id == "ENT-INPUT-002"
        }

        filtered: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for f in findings:
            # Suppress ENT-INPUT-001 if ENT-INPUT-002 was reported for this endpoint
            if f.rule_id == "ENT-INPUT-001" and (f.file, f.symbol) in inconsistent_endpoints:
                continue

            if f.fingerprint in seen_fingerprints:
                continue

            seen_fingerprints.add(f.fingerprint)
            filtered.append(f)

        # Sort deterministically
        filtered.sort(key=lambda x: (x.file, x.line_start, x.rule_id, x.fingerprint))
        return filtered
