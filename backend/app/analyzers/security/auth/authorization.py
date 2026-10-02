"""Authorization Consistency Analyzer orchestrating Phase 5 authorization rules."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.analyzers.rules.base import BaseRule
from app.analyzers.security.auth.rules import (
    DuplicatedAuthorizationRule,
    InconsistentAuthorizationRule,
    PotentiallyMissingAuthorizationRule,
)
from app.analyzers.security.frameworks import FrameworkRouteDetector
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers.security.authorization")


class AuthorizationConsistencyAnalyzer(BaseAnalyzer):
    """Analyzer detecting Authorization Consistency Debt in Python web applications.

    Enforces deterministic AST checks for:
    - ENT-AUTHZ-001: Potentially Missing Authorization Check
    - ENT-AUTHZ-002: Inconsistent Authorization Enforcement
    - ENT-AUTHZ-003: Duplicated Authorization Logic
    """

    def __init__(self, rules: Sequence[BaseRule] | None = None) -> None:
        if rules is not None:
            self._rules = list(rules)
        else:
            self.rule_missing = PotentiallyMissingAuthorizationRule()
            self.rule_inconsistent = InconsistentAuthorizationRule()
            self.rule_duplicated = DuplicatedAuthorizationRule()
            self._rules = [
                self.rule_missing,
                self.rule_inconsistent,
                self.rule_duplicated,
            ]

    @property
    def analyzer_id(self) -> str:
        return "authorization_consistency_analyzer"

    @property
    def name(self) -> str:
        return "Authorization Consistency Analyzer"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHORIZATION_CONSISTENCY

    @property
    def supported_languages(self) -> set[SupportedLanguage]:
        return {SupportedLanguage.PYTHON}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [r.definition for r in self._rules]

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute deterministic static analysis across all valid Python files in context."""
        raw_findings: list[Finding] = []
        valid_python_contexts = context.get_valid_python_contexts()

        for py_ctx in valid_python_contexts:
            try:
                endpoints = FrameworkRouteDetector.extract_endpoints(py_ctx)
                if not endpoints:
                    continue

                file_findings: list[Finding] = []

                # Rule 001: Missing authorization on privileged endpoints
                missing_findings = self.rule_missing.analyze_file(py_ctx)
                file_findings.extend(missing_findings)

                # Rule 002: Inconsistent authorization within route groups
                inconsistent_findings = self.rule_inconsistent.analyze_endpoint_groups(
                    py_ctx, endpoints
                )
                file_findings.extend(inconsistent_findings)

                # Rule 003: Duplicated authorization logic
                duplicated_findings = self.rule_duplicated.analyze_endpoints_for_duplication(
                    py_ctx, endpoints
                )
                file_findings.extend(duplicated_findings)

                # Deduplication & suppression:
                # If an endpoint has ENT-AUTHZ-002 (inconsistency with peer routes),
                # suppress ENT-AUTHZ-001 on that same endpoint.
                suppressed = self._suppress_overlapping_findings(file_findings)
                raw_findings.extend(suppressed)

            except Exception as exc:
                logger.warning(
                    "Authorization analyzer failed on '%s': %s",
                    py_ctx.file_path,
                    exc,
                )

        # Deterministic global sorting: (file, line_start, rule_id, id)
        return sorted(
            raw_findings,
            key=lambda f: (f.file, f.line_start, f.rule_id, f.id),
        )

    def _suppress_overlapping_findings(self, findings: list[Finding]) -> list[Finding]:
        """Suppress ENT-AUTHZ-001 on an endpoint if ENT-AUTHZ-002 fired on that exact endpoint."""
        inconsistent_lines = {
            (f.file, f.line_start) for f in findings if f.rule_id == "ENT-AUTHZ-002"
        }

        result: list[Finding] = []
        for f in findings:
            if f.rule_id == "ENT-AUTHZ-001" and (f.file, f.line_start) in inconsistent_lines:
                # Suppress generic missing authorization finding in favor of specific inconsistency finding
                continue
            result.append(f)
        return result
