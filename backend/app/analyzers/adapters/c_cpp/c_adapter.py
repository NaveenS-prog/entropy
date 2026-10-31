"""Language adapter for C source code."""

from __future__ import annotations

from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.analyzers.adapters.c_cpp.c_rules import (
    RULE_C_001,
    RULE_C_002,
    RULE_C_003,
    check_c_rules,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile


class CLanguageAdapter(BaseLanguageAdapter):
    """Adapter providing static analysis for C source files."""

    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.C

    @property
    def name(self) -> str:
        return "C Security & Buffer Safety Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {DebtCategory.INPUT_VALIDATION}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_C_001, RULE_C_002, RULE_C_003]

    def check_tool_availability(self) -> ToolStatus:
        """Check availability of cppcheck or clang-tidy on the host system."""
        cppcheck_status = self.probe_executable("cppcheck")
        if cppcheck_status.available:
            return cppcheck_status
        clang_status = self.probe_executable("clang-tidy")
        if clang_status.available:
            return clang_status
        return ToolStatus(
            tool_name="cppcheck",
            available=False,
            message="Neither cppcheck nor clang-tidy was detected on PATH. Using built-in deterministic static analyzer.",
        )

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        if file.language != SupportedLanguage.C:
            return []
        return check_c_rules(file)
