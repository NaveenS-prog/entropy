"""Central registry and coordinator for language static analysis adapters."""

from __future__ import annotations

import logging
from typing import Any

from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.analyzers.adapters.c_cpp.c_adapter import CLanguageAdapter
from app.analyzers.adapters.c_cpp.cpp_adapter import CppLanguageAdapter
from app.analyzers.adapters.go.go_adapter import GoLanguageAdapter
from app.analyzers.adapters.java.java_adapter import JavaLanguageAdapter
from app.analyzers.adapters.jsts.jsts_adapter import (
    JavaScriptLanguageAdapter,
    TypeScriptLanguageAdapter,
)
from app.analyzers.adapters.php.php_adapter import PhpLanguageAdapter
from app.analyzers.adapters.rust.rust_adapter import RustLanguageAdapter
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

logger = logging.getLogger("entropy.analyzers.adapters")


class LanguageAdapterRegistry:
    """Registry coordinating language-specific static analysis adapters.

    Makes future language additions modular: implementing a BaseLanguageAdapter
    and calling registry.register() seamlessly exposes its rules, findings,
    and tool reporting across Entropy.
    """

    def __init__(self) -> None:
        self._adapters: dict[SupportedLanguage, BaseLanguageAdapter] = {}

    def register(self, adapter: BaseLanguageAdapter) -> None:
        """Register a language adapter instance."""
        self._adapters[adapter.language] = adapter
        logger.debug("Registered language adapter: %s for %s", adapter.name, adapter.language.value)

    def get_adapter(self, language: SupportedLanguage | str) -> BaseLanguageAdapter | None:
        """Retrieve adapter for a given language."""
        if isinstance(language, str):
            try:
                language = SupportedLanguage(language.lower())
            except ValueError:
                return None
        return self._adapters.get(language)

    get = get_adapter

    def get_all(self) -> list[BaseLanguageAdapter]:
        """Return all registered adapters."""
        return list(self._adapters.values())

    def get_supported_languages(self) -> set[SupportedLanguage]:
        """Return set of all languages backed by active adapters."""
        return set(self._adapters.keys())

    def get_rules(self) -> list[RuleDefinition]:
        """Aggregate all rule definitions across all adapters."""
        rules: list[RuleDefinition] = []
        for adapter in self._adapters.values():
            rules.extend(adapter.rules)
        return rules

    def get_rules_for_category(self, category: DebtCategory) -> list[RuleDefinition]:
        """Return all rules across all adapters targeting a given debt category."""
        return [r for r in self.get_rules() if r.category == category]

    def check_all_tools(self) -> dict[str, ToolStatus]:
        """Check availability of external tools across all registered adapters."""
        return {
            adapter.language.value: adapter.check_tool_availability()
            for adapter in self._adapters.values()
        }

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        """Route a single parsed file to its corresponding language adapter."""
        adapter = self.get_adapter(file.language)
        if not adapter:
            return []
        try:
            return adapter.analyze_file(file)
        except Exception as exc:
            logger.error(
                "Adapter '%s' failed on file '%s': %s",
                adapter.name,
                file.relative_path,
                exc,
                exc_info=True,
            )
            return []

    def analyze_files(self, files: list[ParsedFile]) -> list[Finding]:
        """Route a list of files across matching language adapters."""
        findings: list[Finding] = []
        for file in files:
            findings.extend(self.analyze_file(file))
        return findings


def create_default_adapter_registry() -> LanguageAdapterRegistry:
    """Create and seed registry with adapters for all 8 requested languages."""
    registry = LanguageAdapterRegistry()
    registry.register(CLanguageAdapter())
    registry.register(CppLanguageAdapter())
    registry.register(RustLanguageAdapter())
    registry.register(JavaLanguageAdapter())
    registry.register(GoLanguageAdapter())
    registry.register(JavaScriptLanguageAdapter())
    registry.register(TypeScriptLanguageAdapter())
    registry.register(PhpLanguageAdapter())
    return registry


# Global default adapter registry instance
default_adapter_registry = create_default_adapter_registry()
