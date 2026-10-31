"""Language adapter for Go source code."""

from __future__ import annotations

from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.analyzers.adapters.go.go_rules import (
    RULE_GO_001,
    RULE_GO_002,
    RULE_GO_003,
    RULE_GO_004,
    check_go_rules,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile


class GoLanguageAdapter(BaseLanguageAdapter):
    """Adapter providing static analysis for Go source files (.go)."""

    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.GO

    @property
    def name(self) -> str:
        return "Go Injection, TLS & Concurrency Safety Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {
            DebtCategory.INPUT_VALIDATION,
            DebtCategory.ARCHITECTURAL_CONSISTENCY,
        }

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_GO_001, RULE_GO_002, RULE_GO_003, RULE_GO_004]

    def check_tool_availability(self) -> ToolStatus:
        """Check availability of go compiler or gosec security scanner."""
        gosec_status = self.probe_executable("gosec")
        if gosec_status.available:
            return gosec_status
        go_status = self.probe_executable("go")
        if go_status.available:
            return ToolStatus(
                tool_name="go",
                available=True,
                path=go_status.path,
                version=go_status.version,
                message="Go SDK detected; gosec is not installed. Using built-in deterministic static analyzer.",
            )
        return ToolStatus(
            tool_name="gosec",
            available=False,
            message="Go toolchain (go, gosec) was not detected on PATH. Using built-in deterministic static analyzer.",
        )

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        if file.language != SupportedLanguage.GO:
            return []
        return check_go_rules(file)
