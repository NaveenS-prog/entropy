"""Language adapter for Java source code."""

from __future__ import annotations

from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.analyzers.adapters.java.java_rules import (
    RULE_JAVA_001,
    RULE_JAVA_002,
    RULE_JAVA_003,
    check_java_rules,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile


class JavaLanguageAdapter(BaseLanguageAdapter):
    """Adapter providing static analysis for Java source files (.java)."""

    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.JAVA

    @property
    def name(self) -> str:
        return "Java Injection & Deserialization Safety Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {DebtCategory.INPUT_VALIDATION}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_JAVA_001, RULE_JAVA_002, RULE_JAVA_003]

    def check_tool_availability(self) -> ToolStatus:
        """Check availability of javac or SpotBugs/PMD on host system."""
        javac_status = self.probe_executable("javac")
        if javac_status.available:
            return javac_status
        return ToolStatus(
            tool_name="javac",
            available=False,
            message="Java SDK compiler (javac) was not detected on PATH. Using built-in deterministic static analyzer.",
        )

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        if file.language != SupportedLanguage.JAVA:
            return []
        return check_java_rules(file)
