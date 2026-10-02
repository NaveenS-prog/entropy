"""Authentication Consistency Analyzer orchestrating Phase 5 authentication rules."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.analyzers.rules.base import BaseRule
from app.analyzers.security.auth.rules import (
    DuplicatedAuthenticationRule,
    InconsistentAuthenticationRule,
    PotentiallyUnprotectedEndpointRule,
)
from app.analyzers.security.frameworks import FrameworkRouteDetector
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers.security.authentication")


class AuthenticationConsistencyAnalyzer(BaseAnalyzer):
    """Analyzer detecting Authentication Consistency Debt in Python web applications.

    Enforces deterministic AST checks for:
    - ENT-AUTH-001: Potentially Unprotected Security-Sensitive Endpoint
    - ENT-AUTH-002: Inconsistent Authentication Enforcement
    - ENT-AUTH-003: Duplicated Local Authentication Logic
    """

    def __init__(self, rules: Sequence[BaseRule] | None = None) -> None:
        if rules is not None:
            self._rules = list(rules)
        else:
            self.rule_unprotected = PotentiallyUnprotectedEndpointRule()
            self.rule_inconsistent = InconsistentAuthenticationRule()
            self.rule_duplicated = DuplicatedAuthenticationRule()
            self._rules = [
                self.rule_unprotected,
                self.rule_inconsistent,
                self.rule_duplicated,
            ]

    @property
    def analyzer_id(self) -> str:
        return "authentication_consistency_analyzer"

    @property
    def name(self) -> str:
        return "Authentication Consistency Analyzer"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.AUTHENTICATION_CONSISTENCY

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

                # Rule 001: Unprotected endpoints
                unprotected_findings = self.rule_unprotected.analyze_file(py_ctx)
                file_findings.extend(unprotected_findings)

                # Rule 002: Inconsistent authentication within route groups
                inconsistent_findings = self.rule_inconsistent.analyze_endpoint_groups(
                    py_ctx, endpoints
                )
                file_findings.extend(inconsistent_findings)

                # Rule 003: Duplicated local auth logic
                duplicated_findings = self.rule_duplicated.analyze_endpoints_for_duplication(
                    py_ctx, endpoints
                )
                file_findings.extend(duplicated_findings)

                # Deduplication & suppression:
                # If an endpoint has ENT-AUTH-002 (inconsistency with peer routes),
                # suppress ENT-AUTH-001 on that same endpoint to avoid double-reporting.
                suppressed = self._suppress_overlapping_findings(file_findings)
                raw_findings.extend(suppressed)

            except Exception as exc:
                logger.warning(
                    "Authentication analyzer failed on '%s': %s",
                    py_ctx.file_path,
                    exc,
                )

        # Deterministic global sorting: (file, line_start, rule_id, id)
        return sorted(
            raw_findings,
            key=lambda f: (f.file, f.line_start, f.rule_id, f.id),
        )

    def _suppress_overlapping_findings(self, findings: list[Finding]) -> list[Finding]:
        """Suppress ENT-AUTH-001 on an endpoint if ENT-AUTH-002 fired on that exact endpoint."""
        inconsistent_lines = {
            (f.file, f.line_start) for f in findings if f.rule_id == "ENT-AUTH-002"
        }

        result: list[Finding] = []
        for f in findings:
            if f.rule_id == "ENT-AUTH-001" and (f.file, f.line_start) in inconsistent_lines:
                # Suppress generic unprotected finding in favor of specific inconsistency finding
                continue
            result.append(f)
        return result
