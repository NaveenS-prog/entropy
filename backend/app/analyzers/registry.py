"""Analyzer registry for discovering, configuring, and executing analyzers."""

import logging

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.analyzers.rules.error_handling.broad_exception import ErrorHandlingDebtAnalyzer
from app.analyzers.security.auth.authentication import AuthenticationConsistencyAnalyzer
from app.analyzers.security.auth.authorization import AuthorizationConsistencyAnalyzer
from app.analyzers.security.logging_secrets import LoggingAndSecretsAnalyzer
from app.analyzers.security.validation import InputValidationConsistencyAnalyzer
from app.models.domain.enums import DebtCategory
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers")


class AnalyzerRegistry:
    """Central registry for all active Entropy static analyzers.

    Facilitates modular extension: new analyzers can be plugged in without
    modifying the core analysis orchestration or scoring engines.
    """

    def __init__(self) -> None:
        self._analyzers: dict[str, BaseAnalyzer] = {}

    def register(self, analyzer: BaseAnalyzer) -> None:
        """Register an analyzer instance."""
        if analyzer.analyzer_id in self._analyzers:
            logger.warning("Overwriting already registered analyzer: %s", analyzer.analyzer_id)
        self._analyzers[analyzer.analyzer_id] = analyzer
        logger.debug("Registered analyzer: %s (%s)", analyzer.name, analyzer.category.value)

    def get_analyzer(self, analyzer_id: str) -> BaseAnalyzer | None:
        """Fetch an analyzer by its ID."""
        return self._analyzers.get(analyzer_id)

    def get_all(self) -> list[BaseAnalyzer]:
        """Return all registered analyzers."""
        return list(self._analyzers.values())

    def get_enabled(self) -> list[BaseAnalyzer]:
        """Return all enabled analyzers."""
        return list(self._analyzers.values())

    def get_by_category(self, category: DebtCategory) -> list[BaseAnalyzer]:
        """Return analyzers targeting a specific debt category."""
        return [a for a in self._analyzers.values() if a.category == category]

    def list_rules(self) -> list[RuleDefinition]:
        """Aggregate all rule definitions across all active analyzers."""
        rules: list[RuleDefinition] = []
        for analyzer in self._analyzers.values():
            rules.extend(analyzer.rules)
        return rules

    def run_all(self, context: AnalysisContext) -> list[Finding]:
        """Execute all registered analyzers sequentially and gather findings."""
        all_findings: list[Finding] = []
        for analyzer in self._analyzers.values():
            try:
                findings = analyzer.analyze(context)
                all_findings.extend(findings)
                logger.info(
                    "Analyzer '%s' finished with %d finding(s)",
                    analyzer.name,
                    len(findings),
                )
            except Exception as e:
                logger.error(
                    "Analyzer '%s' failed unexpectedly: %s",
                    analyzer.analyzer_id,
                    e,
                    exc_info=True,
                )
        return all_findings

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Alias for run_all executing all enabled analyzers."""
        return self.run_all(context)


def create_default_registry() -> AnalyzerRegistry:
    """Create and seed the default registry with production-ready analyzers."""
    registry = AnalyzerRegistry()
    registry.register(ErrorHandlingDebtAnalyzer())
    registry.register(AuthenticationConsistencyAnalyzer())
    registry.register(AuthorizationConsistencyAnalyzer())
    registry.register(InputValidationConsistencyAnalyzer())
    registry.register(LoggingAndSecretsAnalyzer())
    return registry


# Global default registry instance
default_registry = create_default_registry()
