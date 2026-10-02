"""Logging and Secret Handling Debt Static Analyzer."""

from __future__ import annotations

import logging

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.analyzers.jsts_rules.logging_secrets import (
    JSHardcodedSecretRule,
    JSInsecureSecretFallbackRule,
    JSSensitiveLogRule,
)
from app.analyzers.rules.base import BaseRule
from app.analyzers.security.logging_secrets.rules import (
    HardcodedSecretPatternRule,
    InconsistentSecretHandlingRule,
    SensitiveDataInLogsRule,
    SensitiveObjectLoggingRule,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers.logging_secrets")


class LoggingAndSecretsAnalyzer(BaseAnalyzer):
    """Static analyzer for identifying logging and secret handling debt."""

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        self._rule_instances: list[BaseRule] = rules or [
            SensitiveDataInLogsRule(),
            HardcodedSecretPatternRule(),
            SensitiveObjectLoggingRule(),
            InconsistentSecretHandlingRule(),
        ]
        self._js_rules = [
            JSSensitiveLogRule(),
            JSHardcodedSecretRule(),
            JSInsecureSecretFallbackRule(),
        ]
        self._rules_meta: list[RuleDefinition] = [r.definition for r in self._rule_instances] + [
            r.definition for r in self._js_rules
        ]

    @property
    def analyzer_id(self) -> str:
        return "logging_and_secrets_analyzer"

    @property
    def name(self) -> str:
        return "Logging & Secret-Handling Debt Analyzer"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.LOGGING_AND_SECRETS

    @property
    def supported_languages(self) -> set[SupportedLanguage]:
        return {
            SupportedLanguage.PYTHON,
            SupportedLanguage.JAVASCRIPT,
            SupportedLanguage.TYPESCRIPT,
        }

    @property
    def rules(self) -> list[RuleDefinition]:
        return self._rules_meta

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute logging and secret handling rules across all Python and JS/TS files in the repository."""
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

        valid_jsts_contexts = context.get_valid_jsts_contexts()
        for js_context in valid_jsts_contexts:
            for js_rule in self._js_rules:
                try:
                    file_findings = js_rule.analyze(js_context)
                    raw_findings.extend(file_findings)
                except Exception as e:
                    logger.error(
                        "JS Rule '%s' failed on file '%s': %s",
                        js_rule.rule_id,
                        js_context.file_path,
                        e,
                        exc_info=True,
                    )

        # Apply deduplication and sorting
        seen_fingerprints: set[str] = set()
        deduped: list[Finding] = []
        for f in raw_findings:
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                deduped.append(f)

        deduped.sort(key=lambda x: (x.file, x.line_start, x.rule_id, x.fingerprint))
        return deduped
