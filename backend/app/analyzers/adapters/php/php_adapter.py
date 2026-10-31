"""Language adapter for PHP source code."""

from __future__ import annotations

from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.analyzers.adapters.php.php_rules import (
    RULE_PHP_001,
    RULE_PHP_002,
    RULE_PHP_003,
    check_php_rules,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile


class PhpLanguageAdapter(BaseLanguageAdapter):
    """Adapter providing static analysis for PHP source files (.php, .phtml)."""

    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.PHP

    @property
    def name(self) -> str:
        return "PHP Injection & File Safety Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {DebtCategory.INPUT_VALIDATION}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_PHP_001, RULE_PHP_002, RULE_PHP_003]

    def check_tool_availability(self) -> ToolStatus:
        """Check availability of php CLI, phpstan, or psalm."""
        php_status = self.probe_executable("php", "-v")
        if php_status.available:
            return php_status
        phpstan_status = self.probe_executable("phpstan")
        if phpstan_status.available:
            return phpstan_status
        return ToolStatus(
            tool_name="php",
            available=False,
            message="PHP runtime or static analyzer (php, phpstan, psalm) was not detected on PATH. Using built-in deterministic static analyzer.",
        )

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        if file.language != SupportedLanguage.PHP:
            return []
        return check_php_rules(file)
