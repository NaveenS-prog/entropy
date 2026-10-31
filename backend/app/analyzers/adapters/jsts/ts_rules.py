"""TypeScript-specific static analysis rules enforcing typing boundaries and project conventions."""

from __future__ import annotations

import re

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# Unsafe type assertion on external data or variables: e.g. req.body as any, val as any, <any>payload, as unknown as any
TS_ANY_CAST_REGEX = re.compile(
    r"(?:(?:req|request|body|params|payload|input|data|res|[a-zA-Z_][a-zA-Z0-9_]*)\s*as\s*any\b|<any>\s*(?:req|request|body|params|payload|input|data|[a-zA-Z_][a-zA-Z0-9_]*)|as\s*unknown\s*as\s*any\b)",
    re.ASCII,
)

# TypeScript suppression directives: @ts-ignore, @ts-nocheck
TS_DIRECTIVE_REGEX = re.compile(
    r"//\s*@ts-(?:ignore|nocheck)\b",
    re.ASCII,
)

# Non-null assertion on external data: req.body!, req.body.token!, req.params.id!
TS_NON_NULL_REGEX = re.compile(
    r"\b(?:req|request|input|data)\.(?:body|query|params|headers)!(?:\.[a-zA-Z0-9_]+!?)*|\b(?:req|request|input|data)\.(?:body|query|params|headers)\.[a-zA-Z0-9_]+!",
    re.ASCII,
)


RULE_TS_001 = RuleDefinition(
    rule_id="ENT-TS-001",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Unsafe 'as any' Type Bypass on External Boundary in TypeScript",
    description="Detects casting external or untrusted request data to 'any' using 'as any' or '<any>', completely disabling compiler type-checking at architectural boundaries.",
    default_severity=Severity.LOW,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.TYPESCRIPT],
    impact_template="Casting external boundary inputs to 'any' allows invalid structures and missing fields to propagate undetected, triggering runtime type errors.",
    recommendation_template="Use TypeScript 'unknown' with type guard functions or schema validation libraries (Zod, TypeBox, Valibot) to safely narrow boundary data.",
    rationale="Subverting TypeScript type checking with 'any' creates hidden architectural type debt.",
)

RULE_TS_002 = RuleDefinition(
    rule_id="ENT-TS-002",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="TypeScript Compiler Suppression Directive (@ts-ignore / @ts-nocheck)",
    description="Detects @ts-ignore or @ts-nocheck directives that suppress TypeScript compiler diagnostic errors rather than resolving them.",
    default_severity=Severity.LOW,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.TYPESCRIPT],
    impact_template="Suppression directives blind the compiler to type mismatches, breaking contracts and masking regressions during refactoring.",
    recommendation_template="Resolve the underlying type mismatch, use proper union types, or use '@ts-expect-error' accompanied by an explicit explanation.",
    rationale="Silencing compiler type errors represents architectural maintenance debt.",
)

RULE_TS_003 = RuleDefinition(
    rule_id="ENT-TS-003",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Unsafe Non-Null Assertion Operator (!) on Request Input in TypeScript",
    description="Detects the non-null assertion operator (!) applied directly to external request properties (req.body, req.params).",
    default_severity=Severity.LOW,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.TYPESCRIPT],
    impact_template="Asserting non-nullness on external inputs crashes with a runtime TypeError if the client omits the expected property.",
    recommendation_template="Use optional chaining (?.) or validate existence with an explicit conditional check or schema parser.",
    rationale="Assuming external inputs are non-null bypasses defensive input validation.",
)


def check_ts_rules(file: ParsedFile) -> list[Finding]:
    """Analyze a TypeScript (.ts, .tsx) file for TypeScript-specific architectural rules."""
    findings: list[Finding] = []

    # Only run on TypeScript files
    if file.language != SupportedLanguage.TYPESCRIPT:
        return []

    for idx, raw_line in enumerate(file.lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        # 1. Check @ts-ignore / @ts-nocheck directives
        match_dir = TS_DIRECTIVE_REGEX.search(raw_line)
        if match_dir:
            evidence = file.extract_snippet(idx, idx)
            directive = match_dir.group(0).strip()
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_TS_002.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol=directive,
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_TS_002.rule_id,
                file=file.relative_path,
                symbol=directive,
                pattern_signature=f"ts_directive:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_TS_002.category,
                    rule_id=RULE_TS_002.rule_id,
                    severity=RULE_TS_002.default_severity,
                    confidence=RULE_TS_002.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=match_dir.start(),
                    column_end=match_dir.end(),
                    symbol=directive,
                    title=f"TypeScript Suppression Directive: {directive}",
                    description=f"Observable TypeScript directive '{directive}' suppresses compiler diagnostics.",
                    evidence=evidence,
                    impact=RULE_TS_002.impact_template,
                    recommendation=RULE_TS_002.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.TYPESCRIPT,
                    reference="https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-9.html#-ts-expect-error-comments",
                    metadata={"directive": directive, "language": "typescript"},
                )
            )

        # 2. Check 'as any' bypass on external input (ignoring pure comments)
        if not stripped.startswith("//") and not stripped.startswith("/*"):
            match_any = TS_ANY_CAST_REGEX.search(raw_line)
            if match_any:
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_TS_001.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol="as any",
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_TS_001.rule_id,
                    file=file.relative_path,
                    symbol="as any",
                    pattern_signature=f"ts_any:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_TS_001.category,
                        rule_id=RULE_TS_001.rule_id,
                        severity=RULE_TS_001.default_severity,
                        confidence=RULE_TS_001.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match_any.start(),
                        column_end=match_any.end(),
                        symbol="as any",
                        title="Unsafe 'as any' Type Bypass in TypeScript",
                        description="External or untrusted request boundary data is unsafely cast to 'any', disabling TypeScript compiler protections.",
                        evidence=evidence,
                        impact=RULE_TS_001.impact_template,
                        recommendation=RULE_TS_001.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.TYPESCRIPT,
                        reference="https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#type-assertions",
                        metadata={"cast": "as any", "language": "typescript"},
                    )
                )

            # 3. Check non-null assertion on external input
            match_non_null = TS_NON_NULL_REGEX.search(raw_line)
            if match_non_null:
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_TS_003.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol="!",
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_TS_003.rule_id,
                    file=file.relative_path,
                    symbol="!",
                    pattern_signature=f"ts_non_null:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_TS_003.category,
                        rule_id=RULE_TS_003.rule_id,
                        severity=RULE_TS_003.default_severity,
                        confidence=RULE_TS_003.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match_non_null.start(),
                        column_end=match_non_null.end(),
                        symbol="!",
                        title="Unsafe Non-Null Assertion on Request Input in TypeScript",
                        description="Non-null assertion operator (!) applied directly to unvalidated HTTP request data.",
                        evidence=evidence,
                        impact=RULE_TS_003.impact_template,
                        recommendation=RULE_TS_003.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.TYPESCRIPT,
                        reference="https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#non-null-assertion-operator-postfix-",
                        metadata={"operator": "!", "language": "typescript"},
                    )
                )

    return findings
