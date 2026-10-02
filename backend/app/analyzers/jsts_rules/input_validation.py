"""JavaScript and TypeScript Input Validation static analysis rules."""

from __future__ import annotations

import re

from app.analyzers.jsts_context import JSTSASTContext
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

VALIDATION_INDICATORS = {
    "zod",
    "joi",
    "yup",
    "ajv",
    "class-validator",
    "valibot",
    "validator",
}

VALIDATION_METHODS = {
    "parse",
    "safeparse",
    "validate",
    "validatesync",
    "isvalid",
    "sanitize",
    "check",
    "assert",
}

SENSITIVE_SINKS = {
    "query",
    "execute",
    "$queryrawunsafe",
    "raw",
    "exec",
    "execsync",
    "spawn",
    "eval",
    "writefile",
    "writefilesync",
}

EXTERNAL_INPUT_PATTERNS = [
    r"req\.body",
    r"req\.query",
    r"req\.params",
    r"request\.body",
    r"request\.query",
    r"request\.params",
]


class JSUnvalidatedInputRule:
    """ENT-INPUT-JS-001: Potentially Unvalidated External Input Reaching Sensitive Sink."""

    rule_id = "ENT-INPUT-JS-001"
    name = "Potentially Unvalidated External Input in Sensitive Sink"
    category = DebtCategory.INPUT_VALIDATION
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description=(
                "External HTTP input (req.body, req.query, req.params) flows into a security-sensitive sink "
                "(database query, shell execution, or eval) without an identifiable validation boundary."
            ),
            default_severity=self.severity,
            default_confidence=self.confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template="Unsanitized external input can lead to injection vulnerabilities, data corruption, or unauthorized operations.",
            recommendation_template="Validate all external request inputs using a schema validation library (e.g. Zod, Joi) before passing to sinks.",
            rationale="Unvalidated input boundaries indicate missing architectural security controls.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1. False-positive check: Does file use schema validation libraries?
        has_validation_library = any(
            any(v in imp.module.lower() for v in VALIDATION_INDICATORS)
            for imp in context.get_imports()
        )

        all_calls = context.get_calls()
        has_schema_parse_call = any(
            c.method_name and c.method_name.lower() in VALIDATION_METHODS
            for c in all_calls
        )

        for call in all_calls:
            method = (call.method_name or "").lower()
            callee = call.callee.lower()

            # Check if this call is a sensitive sink
            is_sink = method in SENSITIVE_SINKS or any(
                sink in callee for sink in ("exec", "eval", "queryrawunsafe")
            )
            if not is_sink:
                continue

            # Check if any argument contains external input
            matched_input: str | None = None
            for arg in call.arguments:
                for pattern in EXTERNAL_INPUT_PATTERNS:
                    if re.search(pattern, arg):
                        matched_input = arg
                        break
                if matched_input:
                    break

            if not matched_input:
                continue

            # False-positive safeguard: If the function or file performs schema parsing
            # and this is a standard parameterized db.query("...", [params]), skip
            if has_validation_library or has_schema_parse_call:
                continue

            # Check if parameterized query: e.g. db.query(sql, [params]) where sql is a constant template
            if len(call.arguments) >= 2 and ("$" in call.arguments[0] or "?" in call.arguments[0]):
                # Parameterized SQL query placeholder
                continue

            snippet = context.extract_snippet(
                call.location.line_start,
                call.location.line_end,
                context_before=1,
                context_after=1,
            )
            sig = f"{call.callee}:{call.location.line_start}"
            fid = Finding.generate_deterministic_id(
                rule_id=self.rule_id,
                file=context.file_path,
                line_start=call.location.line_start,
                line_end=call.location.line_end,
                symbol=call.callee,
                evidence_signature=sig,
            )
            fp = Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=context.file_path,
                symbol=call.callee,
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
                    line_start=call.location.line_start,
                    line_end=call.location.line_end,
                    column_start=call.location.col_start,
                    column_end=call.location.col_end,
                    symbol=call.callee,
                    title="Potentially Unvalidated External Input in Sensitive Sink",
                    description=(
                        f"External input '{matched_input}' is passed directly to sensitive sink '{call.callee}' "
                        f"in '{context.file_path}' without an identifiable validation boundary."
                    ),
                    evidence=snippet,
                    impact="Permits injection and tampering if incoming HTTP payloads deviate from expected constraints.",
                    recommendation="Enforce schema validation (e.g. with Zod or Joi) before invoking sensitive operations.",
                )
            )

        return findings
