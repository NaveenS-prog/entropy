"""DOM and dynamic code execution rules for JavaScript and TypeScript."""

from __future__ import annotations

import re

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# Unsafe DOM manipulation: innerHTML, outerHTML, document.write
JS_DOM_ASSIGN_REGEX = re.compile(
    r"\b([a-zA-Z0-9_\$.\(\)]+)\.(?:innerHTML|outerHTML)\s*=\s*([^;]+)",
    re.ASCII,
)
JS_DOC_WRITE_REGEX = re.compile(r"\bdocument\.(?:write|writeln)\s*\(\s*([^)]+)\)", re.ASCII)

# Dynamic code execution
JS_EVAL_REGEX = re.compile(r"\b(?:eval|new\s+Function)\s*\(\s*([^)]+)\)", re.ASCII)


RULE_JS_002 = RuleDefinition(
    rule_id="ENT-JS-002",
    category=DebtCategory.INPUT_VALIDATION,
    title="Unsafe DOM Manipulation via innerHTML / document.write",
    description="Detects direct assignments to innerHTML / outerHTML or document.write() without DOMPurify or explicit HTML sanitization.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    impact_template="Assigning unsanitized input to innerHTML or document.write executes arbitrary scripts in the victim's browser context (Cross-Site Scripting, XSS).",
    recommendation_template="Use textContent or innerText for plain text, or sanitize HTML content with DOMPurify.sanitize() before setting innerHTML.",
    rationale="Direct DOM HTML injection undermines browser-side input validation and security boundaries.",
)

RULE_JS_003 = RuleDefinition(
    rule_id="ENT-JS-003",
    category=DebtCategory.INPUT_VALIDATION,
    title="Dynamic Code Evaluation via eval() or Function()",
    description="Detects invocations of eval() or new Function() with runtime dynamic expressions.",
    default_severity=Severity.CRITICAL,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    impact_template="Evaluating dynamic code at runtime bypasses engine optimizations and permits arbitrary remote JavaScript execution.",
    recommendation_template="Use JSON.parse() for structured data and refactor dynamic logic into static JavaScript functions.",
    rationale="eval() creates severe runtime code execution debt.",
)


def _strip_jsts_comments(line: str, in_block: bool) -> tuple[str, bool]:
    if in_block:
        if "*/" in line:
            _, after = line.split("*/", 1)
            rest, still_in = _strip_jsts_comments(after, False)
            return (" " * (len(line) - len(rest))) + rest, still_in
        return " " * len(line), True

    if "/*" in line:
        before, after = line.split("/*", 1)
        if "*/" in after:
            _, end_after = after.split("*/", 1)
            processed_end, _ = _strip_jsts_comments(end_after, False)
            return before + " " * (len(line) - len(before) - len(processed_end)) + processed_end, False
        return before + " " * (len(line) - len(before)), True

    if "//" in line:
        before, _ = line.split("//", 1)
        return before, False

    return line, False


def check_js_dom_rules(file: ParsedFile) -> list[Finding]:
    """Check JavaScript / TypeScript files for unsafe DOM and code evaluation patterns."""
    findings: list[Finding] = []
    in_block = False

    for idx, raw_line in enumerate(file.lines, start=1):
        clean_line, in_block = _strip_jsts_comments(raw_line, in_block)
        stripped = clean_line.strip()
        if not stripped:
            continue

        # 1. Check innerHTML / outerHTML / document.write
        match_dom = JS_DOM_ASSIGN_REGEX.search(clean_line)
        match_write = JS_DOC_WRITE_REGEX.search(clean_line)
        if match_dom or match_write:
            match = match_dom or match_write
            rhs = match_dom.group(2).strip() if match_dom else match_write.group(1).strip()
            # If sanitized with DOMPurify, skip
            if "DOMPurify" not in rhs and "sanitize" not in rhs.lower():
                evidence = file.extract_snippet(idx, idx)
                sym = "innerHTML" if "innerHTML" in clean_line else ("outerHTML" if "outerHTML" in clean_line else "document.write")
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_JS_002.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol=sym,
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_JS_002.rule_id,
                    file=file.relative_path,
                    symbol=sym,
                    pattern_signature=f"js_dom:{sym}:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_JS_002.category,
                        rule_id=RULE_JS_002.rule_id,
                        severity=RULE_JS_002.default_severity,
                        confidence=RULE_JS_002.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match.start(),
                        column_end=match.end(),
                        symbol=sym,
                        title=f"Unsafe DOM HTML Assignment via {sym}",
                        description=f"Direct assignment to '{sym}' observed without identifiable HTML sanitization (e.g. DOMPurify).",
                        evidence=evidence,
                        impact=RULE_JS_002.impact_template,
                        recommendation=RULE_JS_002.recommendation_template,
                        fingerprint=fingerprint,
                        language=file.language,
                        reference="https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        metadata={"property": sym, "language": file.language.value},
                    )
                )

        # 2. Check eval / new Function
        match_eval = JS_EVAL_REGEX.search(clean_line)
        if match_eval:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_JS_003.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="eval",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_JS_003.rule_id,
                file=file.relative_path,
                symbol="eval",
                pattern_signature=f"js_eval:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_JS_003.category,
                    rule_id=RULE_JS_003.rule_id,
                    severity=RULE_JS_003.default_severity,
                    confidence=RULE_JS_003.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=match_eval.start(),
                    column_end=match_eval.end(),
                    symbol="eval",
                    title="Dynamic Code Evaluation via eval() in JavaScript",
                    description="Call to dynamic evaluation function 'eval()' or 'Function()' detected.",
                    evidence=evidence,
                    impact=RULE_JS_003.impact_template,
                    recommendation=RULE_JS_003.recommendation_template,
                    fingerprint=fingerprint,
                    language=file.language,
                    reference="https://cwe.mitre.org/data/definitions/95.html",
                    metadata={"function": "eval", "language": file.language.value},
                )
            )

    return findings
