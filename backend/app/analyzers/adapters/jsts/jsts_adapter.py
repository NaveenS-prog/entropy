"""JavaScript and TypeScript language adapters."""

from __future__ import annotations

from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.analyzers.adapters.jsts.dom_rules import (
    RULE_JS_002,
    RULE_JS_003,
    check_js_dom_rules,
)
from app.analyzers.adapters.jsts.ts_rules import (
    RULE_TS_001,
    RULE_TS_002,
    RULE_TS_003,
    check_ts_rules,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile


class JavaScriptLanguageAdapter(BaseLanguageAdapter):
    """Adapter providing static analysis for JavaScript files (.js, .jsx, .mjs, .cjs)."""

    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.JAVASCRIPT

    @property
    def name(self) -> str:
        return "JavaScript DOM & Dynamic Execution Safety Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {DebtCategory.INPUT_VALIDATION}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_JS_002, RULE_JS_003]

    def check_tool_availability(self) -> ToolStatus:
        """Check availability of node and npm / eslint."""
        node_status = self.probe_executable("node")
        if node_status.available:
            return node_status
        return ToolStatus(
            tool_name="node",
            available=False,
            message="Node.js runtime was not detected on PATH. Using built-in Tree-sitter static analyzer.",
        )

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        if file.language not in (SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT):
            return []
        return check_js_dom_rules(file)


class TypeScriptLanguageAdapter(BaseLanguageAdapter):
    """Adapter providing static analysis specifically for TypeScript files (.ts, .tsx, .mts, .cts)."""

    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.TYPESCRIPT

    @property
    def name(self) -> str:
        return "TypeScript Type Safety & Convention Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {
            DebtCategory.ARCHITECTURAL_CONSISTENCY,
            DebtCategory.INPUT_VALIDATION,
        }

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_JS_002, RULE_JS_003, RULE_TS_001, RULE_TS_002, RULE_TS_003]

    def check_tool_availability(self) -> ToolStatus:
        """Check availability of tsc compiler or eslint."""
        tsc_status = self.probe_executable("tsc")
        if tsc_status.available:
            return tsc_status
        node_status = self.probe_executable("node")
        if node_status.available:
            return ToolStatus(
                tool_name="node",
                available=True,
                path=node_status.path,
                version=node_status.version,
                message="Node.js detected; tsc is not globally installed. Using built-in Tree-sitter static analyzer.",
            )
        return ToolStatus(
            tool_name="tsc",
            available=False,
            message="TypeScript compiler (tsc) was not detected on PATH. Using built-in Tree-sitter static analyzer.",
        )

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        if file.language != SupportedLanguage.TYPESCRIPT:
            return []
        # Run both DOM rules and TypeScript-specific architectural rules
        dom_findings = check_js_dom_rules(file)
        ts_findings = check_ts_rules(file)
        return dom_findings + ts_findings
