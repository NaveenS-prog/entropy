"""Deterministic static analysis rules for Java language codebases."""

from __future__ import annotations

import re

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# Java SQL execution methods
JAVA_SQL_METHOD_REGEX = re.compile(
    r"\b(executeQuery|executeUpdate|execute|createQuery|createNativeQuery)\s*\(\s*([^)]+)\)",
    re.ASCII,
)

# Unsafe deserialization
JAVA_DESERIALIZATION_REGEX = re.compile(
    r"\b(?:(?:new\s+ObjectInputStream|ObjectInputStream\s+[a-zA-Z0-9_]+)\b.*?\.readObject\(\)|\.readObject\(\))",
    re.ASCII,
)

# Command injection
JAVA_EXEC_REGEX = re.compile(
    r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(\s*([^)]+)\)",
    re.ASCII,
)


RULE_JAVA_001 = RuleDefinition(
    rule_id="ENT-JAVA-001",
    category=DebtCategory.INPUT_VALIDATION,
    title="SQL Injection via Dynamic Concatenation in Java",
    description="Detects SQL queries constructed with runtime string concatenation in JDBC statement or ORM execution calls.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.JAVA],
    impact_template="Unparameterized SQL concatenation allows user input to modify query structure, leading to unauthorized data exposure, corruption, or administrative bypass.",
    recommendation_template="Use PreparedStatement with '?' parameter placeholders (e.g. conn.prepareStatement(\"SELECT ... WHERE id = ?\")) instead of string concatenation.",
    rationale="Dynamic SQL queries in JDBC and JPA code represent critical input-validation architectural debt.",
)

RULE_JAVA_002 = RuleDefinition(
    rule_id="ENT-JAVA-002",
    category=DebtCategory.INPUT_VALIDATION,
    title="Unsafe Object Deserialization in Java",
    description="Detects direct use of ObjectInputStream.readObject() without explicit deserialization filtering or Look-Ahead validation.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.JAVA],
    impact_template="Deserializing untrusted byte streams with standard Java serialization triggers remote code execution via gadget chains.",
    recommendation_template="Avoid native Java serialization for external data; use JSON (e.g. Jackson with safe typing) or configure an ObjectInputFilter.",
    rationale="Standard Java ObjectInputStream is inherently vulnerable when processing untrusted input.",
)

RULE_JAVA_003 = RuleDefinition(
    rule_id="ENT-JAVA-003",
    category=DebtCategory.INPUT_VALIDATION,
    title="Command Injection via Process Execution in Java",
    description="Detects command strings constructed with concatenation passed to Runtime.getRuntime().exec() or ProcessBuilder.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.JAVA],
    impact_template="Concatenating unvalidated data into process execution strings permits arbitrary operating system command execution.",
    recommendation_template="Use ProcessBuilder with separated command and argument tokens (e.g. new ProcessBuilder(\"cmd\", arg1, arg2)) without shell interpolation.",
    rationale="Invoking OS processes with dynamic strings creates critical security debt.",
)


def _strip_java_comments(line: str, in_block: bool) -> tuple[str, bool]:
    if in_block:
        if "*/" in line:
            _, after = line.split("*/", 1)
            rest, still_in = _strip_java_comments(after, False)
            return (" " * (len(line) - len(rest))) + rest, still_in
        return " " * len(line), True

    if "/*" in line:
        before, after = line.split("/*", 1)
        if "*/" in after:
            _, end_after = after.split("*/", 1)
            processed_end, _ = _strip_java_comments(end_after, False)
            return before + " " * (len(line) - len(before) - len(processed_end)) + processed_end, False
        return before + " " * (len(line) - len(before)), True

    if "//" in line:
        before, _ = line.split("//", 1)
        return before, False

    return line, False


def check_java_rules(file: ParsedFile) -> list[Finding]:
    """Analyze a Java source file and return deterministic findings."""
    findings: list[Finding] = []
    in_block = False

    for idx, raw_line in enumerate(file.lines, start=1):
        clean_line, in_block = _strip_java_comments(raw_line, in_block)
        stripped = clean_line.strip()
        if not stripped:
            continue

        # 1. Check SQL injection via string concatenation
        is_sql_concat = False
        method_name = "executeQuery"
        match_sql = JAVA_SQL_METHOD_REGEX.search(clean_line)
        if match_sql:
            method_name = match_sql.group(1)
            args_str = match_sql.group(2).strip()
            if "+" in args_str and ('"' in args_str or "sql" in args_str.lower() or "query" in args_str.lower()):
                is_sql_concat = True
        elif "+" in clean_line and '"' in clean_line:
            lower = clean_line.lower()
            if any(k in lower for k in ["select ", "insert into", "update ", "delete from"]):
                is_sql_concat = True
                method_name = "query_concat"

        if is_sql_concat:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_JAVA_001.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol=method_name,
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_JAVA_001.rule_id,
                file=file.relative_path,
                symbol=method_name,
                pattern_signature=f"java_sqli:{method_name}:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_JAVA_001.category,
                    rule_id=RULE_JAVA_001.rule_id,
                    severity=RULE_JAVA_001.default_severity,
                    confidence=RULE_JAVA_001.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=clean_line.find("+") if "+" in clean_line else 0,
                    column_end=len(clean_line),
                    symbol=method_name,
                    title=f"SQL Injection via Concatenation in {method_name}()",
                    description=f"Query constructed using dynamic string concatenation in Java.",
                    evidence=evidence,
                    impact=RULE_JAVA_001.impact_template,
                    recommendation=RULE_JAVA_001.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.JAVA,
                    reference="https://owasp.org/www-community/attacks/SQL_Injection",
                    metadata={"method": method_name, "language": "java"},
                )
            )

        # 2. Check unsafe deserialization
        match_deser = re.search(r"\b[a-zA-Z0-9_]*\.readObject\s*\(", clean_line)
        if match_deser:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_JAVA_002.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="readObject",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_JAVA_002.rule_id,
                file=file.relative_path,
                symbol="readObject",
                pattern_signature=f"java_deser:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_JAVA_002.category,
                    rule_id=RULE_JAVA_002.rule_id,
                    severity=RULE_JAVA_002.default_severity,
                    confidence=RULE_JAVA_002.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=clean_line.find("readObject"),
                    column_end=clean_line.find("readObject") + 12,
                    symbol="readObject",
                    title="Unsafe Object Deserialization in Java",
                    description="Observable call to 'ObjectInputStream.readObject()' without safe ObjectInputFilter boundary.",
                    evidence=evidence,
                    impact=RULE_JAVA_002.impact_template,
                    recommendation=RULE_JAVA_002.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.JAVA,
                    reference="https://cwe.mitre.org/data/definitions/502.html",
                    metadata={"method": "readObject", "language": "java"},
                )
            )

        # 3. Check command execution with dynamic string
        match_exec = JAVA_EXEC_REGEX.search(clean_line)
        if match_exec:
            args_str = match_exec.group(1).strip()
            if "+" in args_str:
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_JAVA_003.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol="exec",
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_JAVA_003.rule_id,
                    file=file.relative_path,
                    symbol="exec",
                    pattern_signature=f"java_exec:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_JAVA_003.category,
                        rule_id=RULE_JAVA_003.rule_id,
                        severity=RULE_JAVA_003.default_severity,
                        confidence=RULE_JAVA_003.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match_exec.start(),
                        column_end=match_exec.end(),
                        symbol="exec",
                        title="Command Injection via Process Execution in Java",
                        description="Dynamic string concatenation detected in command execution call.",
                        evidence=evidence,
                        impact=RULE_JAVA_003.impact_template,
                        recommendation=RULE_JAVA_003.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.JAVA,
                        reference="https://cwe.mitre.org/data/definitions/78.html",
                        metadata={"method": "exec", "language": "java"},
                    )
                )

    return findings
