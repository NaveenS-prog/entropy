"""Deterministic static analysis rules for C language codebases."""

from __future__ import annotations

import re
from typing import Any

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# Regexes for comment removal
LINE_COMMENT_PATTERN = re.compile(r"//.*$")
BLOCK_COMMENT_START = re.compile(r"/\*.*")
BLOCK_COMMENT_END = re.compile(r".*\*/")

# 1. Dangerous buffer functions
DANGEROUS_C_BUFFER_FUNCS = {
    "gets": (Severity.CRITICAL, "C11 deprecated gets() has no buffer bounds check and guarantees buffer overflow vulnerabilities."),
    "strcpy": (Severity.HIGH, "strcpy() does not check destination buffer boundaries; unbounded copying leads to stack/heap overflows."),
    "strcat": (Severity.HIGH, "strcat() does not check destination buffer length; concatenating unbounded input overflows buffer bounds."),
    "sprintf": (Severity.HIGH, "sprintf() writes unbounded formatted data into fixed buffer without boundary checks."),
    "vsprintf": (Severity.HIGH, "vsprintf() writes unbounded variable argument lists into fixed buffer."),
}

DANGEROUS_FUNC_CALL_REGEX = re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(", re.ASCII)

# Safe function names that should not be falsely matched
SAFE_BUFFER_ALTERNATIVES = {"strncpy", "strncat", "snprintf", "vsnprintf", "strlcpy", "strlcat"}

# 2. Unsafe scanf format without width
# Matches scanf("%s", ...) or fscanf(fp, "%s", ...) without width like %64s
SCANF_CALL_REGEX = re.compile(r"\b(scanf|fscanf|sscanf)\s*\(\s*([^,\)]+,\s*)?\"([^\"]*)\"", re.ASCII)

# 3. Command injection via system / popen
SYSTEM_CALL_REGEX = re.compile(r"\b(system|popen)\s*\(", re.ASCII)


RULE_C_001 = RuleDefinition(
    rule_id="ENT-C-001",
    category=DebtCategory.INPUT_VALIDATION,
    title="Dangerous Unbounded Buffer Operation in C",
    description="Identifies legacy unbounded C string and memory copying APIs (strcpy, strcat, gets, sprintf, vsprintf) that do not enforce buffer boundary constraints.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.C],
    impact_template="Unbounded buffer writes allow external data to exceed allocated buffer space, resulting in memory corruption and arbitrary code execution.",
    recommendation_template="Replace unbounded operations with bounded counterparts: use snprintf instead of sprintf, and strncpy/strlcpy with explicit size limits.",
    rationale="Using unbounded buffer functions represents architectural memory safety debt across native C modules.",
)

RULE_C_002 = RuleDefinition(
    rule_id="ENT-C-002",
    category=DebtCategory.INPUT_VALIDATION,
    title="Unsafe Format String Input Handling in C",
    description="Detects scanf/fscanf input functions using %s or %[ without field-width limits, allowing unbounded input into destination buffers.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.C],
    impact_template="Reading user input with unbounded %s specifiers overflows destination character buffers when input exceeds expected length.",
    recommendation_template="Specify maximum buffer width in the format specifier (e.g. '%63s' for a 64-byte buffer) or use fgets().",
    rationale="Unbounded scanf specifiers are a classic source of remote memory-safety vulnerabilities in C services.",
)

RULE_C_003 = RuleDefinition(
    rule_id="ENT-C-003",
    category=DebtCategory.INPUT_VALIDATION,
    title="Command Injection via Shell Invocation in C",
    description="Detects invocations of system() or popen() in C, which pass command strings to the system shell for interpretation.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.C],
    impact_template="Executing commands via the shell introduces command injection and shell metacharacter expansion risks if input is not rigorously validated.",
    recommendation_template="Avoid system() and popen(); invoke executables directly using execve() or posix_spawn() with explicit argument vectors.",
    rationale="Invoking the shell directly creates an architectural security debt risk for privileged or network-facing native services.",
)


def _strip_comments_from_line(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Strip C line and block comments from a line, preserving character count for line positions."""
    if in_block_comment:
        if "*/" in line:
            _, after = line.split("*/", 1)
            rest, still_in = _strip_comments_from_line(after, False)
            return (" " * (len(line) - len(rest))) + rest, still_in
        return " " * len(line), True

    # Check for block comment start
    if "/*" in line:
        before, after = line.split("/*", 1)
        if "*/" in after:
            _, end_after = after.split("*/", 1)
            processed_end, _ = _strip_comments_from_line(end_after, False)
            return before + " " * (len(line) - len(before) - len(processed_end)) + processed_end, False
        return before + " " * (len(line) - len(before)), True

    # Line comment
    if "//" in line:
        before, _ = line.split("//", 1)
        return before, False

    return line, False


def check_c_rules(file: ParsedFile) -> list[Finding]:
    """Analyze a C source file and yield deterministic findings."""
    findings: list[Finding] = []
    in_block = False

    for idx, raw_line in enumerate(file.lines, start=1):
        clean_line, in_block = _strip_comments_from_line(raw_line, in_block)
        stripped = clean_line.strip()
        if not stripped:
            continue

        # 1. Check dangerous buffer functions
        for match in DANGEROUS_FUNC_CALL_REGEX.finditer(clean_line):
            fn_name = match.group(1)
            # Verify not part of a larger safe word
            col = match.start()
            if col > 0 and clean_line[col - 1] in "_a-zA-Z0-9":
                continue
            
            sev, desc_detail = DANGEROUS_C_BUFFER_FUNCS.get(fn_name, (Severity.HIGH, "Dangerous buffer function."))
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_C_001.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol=fn_name,
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_C_001.rule_id,
                file=file.relative_path,
                symbol=fn_name,
                pattern_signature=f"{fn_name}:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_C_001.category,
                    rule_id=RULE_C_001.rule_id,
                    severity=sev,
                    confidence=RULE_C_001.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=col,
                    column_end=match.end(),
                    symbol=fn_name,
                    title=f"Dangerous C Buffer Operation: {fn_name}()",
                    description=f"Observable call to '{fn_name}()' detected. {desc_detail}",
                    evidence=evidence,
                    impact=RULE_C_001.impact_template,
                    recommendation=RULE_C_001.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.C,
                    reference="https://cwe.mitre.org/data/definitions/120.html",
                    metadata={"function": fn_name, "language": "c"},
                )
            )

        # 2. Check scanf without width
        for match in SCANF_CALL_REGEX.finditer(clean_line):
            fn_name = match.group(1)
            fmt_str = match.group(3)
            # Check for %s or %[ without integer width (e.g. %s vs %64s)
            if re.search(r"%(\[[^\]]+\]|s)", fmt_str) and not re.search(r"%\d+(\[[^\]]+\]|s)", fmt_str):
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_C_002.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol=fn_name,
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_C_002.rule_id,
                    file=file.relative_path,
                    symbol=fn_name,
                    pattern_signature=f"scanf_unbounded:{fmt_str}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_C_002.category,
                        rule_id=RULE_C_002.rule_id,
                        severity=RULE_C_002.default_severity,
                        confidence=RULE_C_002.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match.start(),
                        column_end=match.end(),
                        symbol=fn_name,
                        title=f"Unbounded Input Format in {fn_name}()",
                        description=f"Call to {fn_name}() with format string '{fmt_str}' lacks maximum buffer width limits.",
                        evidence=evidence,
                        impact=RULE_C_002.impact_template,
                        recommendation=RULE_C_002.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.C,
                        reference="https://cwe.mitre.org/data/definitions/120.html",
                        metadata={"function": fn_name, "format": fmt_str, "language": "c"},
                    )
                )

        # 3. Check system / popen shell execution
        for match in SYSTEM_CALL_REGEX.finditer(clean_line):
            fn_name = match.group(1)
            col = match.start()
            if col > 0 and clean_line[col - 1] in "_a-zA-Z0-9":
                continue
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_C_003.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol=fn_name,
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_C_003.rule_id,
                file=file.relative_path,
                symbol=fn_name,
                pattern_signature=f"shell_exec:{fn_name}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_C_003.category,
                    rule_id=RULE_C_003.rule_id,
                    severity=RULE_C_003.default_severity,
                    confidence=RULE_C_003.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=col,
                    column_end=match.end(),
                    symbol=fn_name,
                    title=f"Direct Shell Execution via {fn_name}() in C",
                    description=f"Call to '{fn_name}()' passes commands to the system shell.",
                    evidence=evidence,
                    impact=RULE_C_003.impact_template,
                    recommendation=RULE_C_003.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.C,
                    reference="https://cwe.mitre.org/data/definitions/78.html",
                    metadata={"function": fn_name, "language": "c"},
                )
            )

    return findings
