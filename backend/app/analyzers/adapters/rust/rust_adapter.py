"""Language adapter for Rust source code."""

from __future__ import annotations

from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.analyzers.adapters.rust.rust_rules import (
    RULE_RUST_001,
    RULE_RUST_002,
    RULE_RUST_003,
    check_rust_rules,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile


class RustLanguageAdapter(BaseLanguageAdapter):
    """Adapter providing static analysis for Rust source files (.rs)."""

    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.RUST

    @property
    def name(self) -> str:
        return "Rust Unsafe & Memory Review Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {
            DebtCategory.ARCHITECTURAL_CONSISTENCY,
            DebtCategory.INPUT_VALIDATION,
        }

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_RUST_001, RULE_RUST_002, RULE_RUST_003]

    def check_tool_availability(self) -> ToolStatus:
        """Check availability of cargo or cargo-audit on host system."""
        cargo_audit_status = self.probe_executable("cargo-audit")
        if cargo_audit_status.available:
            return cargo_audit_status
        cargo_status = self.probe_executable("cargo")
        if cargo_status.available:
            return ToolStatus(
                tool_name="cargo",
                available=True,
                path=cargo_status.path,
                version=cargo_status.version,
                message="cargo toolchain detected; cargo-audit is not installed. Using built-in deterministic static analyzer.",
            )
        return ToolStatus(
            tool_name="cargo-audit",
            available=False,
            message="Rust toolchain (cargo, cargo-audit) was not detected on PATH. Using built-in deterministic static analyzer.",
        )

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        if file.language != SupportedLanguage.RUST:
            return []
        return check_rust_rules(file)
