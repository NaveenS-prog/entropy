"""JavaScript and TypeScript Error Handling static analysis rules."""

from __future__ import annotations

from app.analyzers.jsts_context import JSTSASTContext
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

INTENTIONAL_IGNORE_TAGS = {"ignore", "intentional", "expected", "suppress", "pass"}


class JSEmptyCatchRule:
    """ENT-ERR-JS-001: Empty Catch Handler."""

    rule_id = "ENT-ERR-JS-001"
    name = "Empty Catch Block"
    category = DebtCategory.ERROR_HANDLING
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description="Catch block contains no statements, discarding errors without handling or logging.",
            default_severity=self.severity,
            default_confidence=self.confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template="Unhandled exceptions are swallowed silently, obscuring root-cause analysis and risking inconsistent system state.",
            recommendation_template="Handle the error explicitly: log it, propagate it, or add structured error-recovery logic.",
            rationale="Empty catch blocks hide critical errors and create silent debt without triggering compilation or runtime errors.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        findings: list[Finding] = []
        for handler in context.get_exception_handlers():
            if not handler.is_empty:
                continue

            # False-positive safeguard: intentional comments like // ignore or // intentional
            if handler.has_comment and handler.comment_text:
                c_low = handler.comment_text.lower()
                if any(tag in c_low for tag in INTENTIONAL_IGNORE_TAGS):
                    continue

            snippet = context.extract_snippet(
                handler.location.line_start,
                handler.location.line_end,
                context_before=1,
                context_after=1,
            )
            sig = f"{handler.location.line_start}:{handler.location.col_start}"
            fid = Finding.generate_deterministic_id(
                rule_id=self.rule_id,
                file=context.file_path,
                line_start=handler.location.line_start,
                line_end=handler.location.line_end,
                symbol=handler.enclosing_function,
                evidence_signature=sig,
            )
            fp = Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=context.file_path,
                symbol=handler.enclosing_function,
                pattern_signature=sig,
            )

            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    file=context.file_path,
                    line_start=handler.location.line_start,
                    line_end=handler.location.line_end,
                    column_start=handler.location.col_start,
                    column_end=handler.location.col_end,
                    symbol=handler.enclosing_function,
                    title="Empty Catch Block",
                    description=(
                        f"Empty catch block in '{context.file_path}' silently swallows exceptions without "
                        "logging, recovery, or propagation."
                    ),
                    evidence=snippet,
                    impact="Errors are completely dropped, hiding application failures and potential security faults.",
                    recommendation="Log the error using a logger or rethrow it after appropriate handling.",
                )
            )

        return findings


class JSSwallowedErrorFallbackRule:
    """ENT-ERR-JS-002: Silently Swallowed Error with Generic Fallback."""

    rule_id = "ENT-ERR-JS-002"
    name = "Silently Swallowed Error with Generic Fallback"
    category = DebtCategory.ERROR_HANDLING
    severity = Severity.LOW
    confidence = Confidence.MEDIUM

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description="Catch block silently swallows error and returns a generic fallback value without logging.",
            default_severity=self.severity,
            default_confidence=self.confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template="Masks operational failures and permits downstream components to process unexpected fallback values.",
            recommendation_template="Log the caught error with context before returning a fallback, or propagate the failure.",
            rationale="Swallowing errors with generic fallbacks masks bugs and complicates production troubleshooting.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        findings: list[Finding] = []
        for handler in context.get_exception_handlers():
            if not handler.returns_fallback:
                continue

            # False-positive safeguard: If error is logged or re-thrown, do not flag
            if handler.has_logging or handler.has_rethrow:
                continue

            # If empty, ENT-ERR-JS-001 handles it
            if handler.is_empty:
                continue

            snippet = context.extract_snippet(
                handler.location.line_start,
                handler.location.line_end,
                context_before=1,
                context_after=1,
            )
            sig = f"{handler.location.line_start}:{handler.fallback_value}"
            fid = Finding.generate_deterministic_id(
                rule_id=self.rule_id,
                file=context.file_path,
                line_start=handler.location.line_start,
                line_end=handler.location.line_end,
                symbol=handler.enclosing_function,
                evidence_signature=sig,
            )
            fp = Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=context.file_path,
                symbol=handler.enclosing_function,
                pattern_signature=sig,
            )

            val_repr = handler.fallback_value or "literal"
            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    file=context.file_path,
                    line_start=handler.location.line_start,
                    line_end=handler.location.line_end,
                    column_start=handler.location.col_start,
                    column_end=handler.location.col_end,
                    symbol=handler.enclosing_function,
                    title="Silently Swallowed Error with Generic Fallback",
                    description=(
                        f"Catch block in '{context.file_path}' catches an error and returns fallback '{val_repr}' "
                        "without any diagnostic logging or notification."
                    ),
                    evidence=snippet,
                    impact="Operational failures are masked, making downstream faults difficult to trace.",
                    recommendation="Log error details before returning a fallback, or throw a descriptive domain exception.",
                )
            )

        return findings
