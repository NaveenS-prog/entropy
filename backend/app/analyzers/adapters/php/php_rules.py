"""Deterministic static analysis rules for PHP language codebases."""

from __future__ import annotations

import re

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# PHP SQL query execution: mysqli_query, $pdo->query, $db->query
PHP_SQL_REGEX = re.compile(
    r"\b(?:mysqli_query|\$[a-zA-Z0-9_]+->query|\$[a-zA-Z0-9_]+->exec)\s*\(\s*([^)]+)\)",
    re.ASCII,
)

# Unsafe file inclusion: include, require, include_once, require_once
PHP_INCLUDE_REGEX = re.compile(
    r"\b(include|require|include_once|require_once)\s*(?:\(|\s+)([^;]+)",
    re.ASCII,
)

# Dynamic code and command execution: eval, system, exec, shell_exec, passthru, backticks
PHP_DANGEROUS_EXEC_REGEX = re.compile(
    r"\b(eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
    re.ASCII,
)


RULE_PHP_001 = RuleDefinition(
    rule_id="ENT-PHP-001",
    category=DebtCategory.INPUT_VALIDATION,
    title="SQL Injection via String Concatenation in PHP",
    description="Detects SQL queries constructed with runtime string concatenation ('.' or variable interpolation) in mysqli or PDO query execution calls.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PHP],
    impact_template="Unparameterized SQL queries in PHP allow external inputs to escape data boundaries and execute arbitrary SQL commands.",
    recommendation_template="Use PDO prepared statements with parameter binding (e.g. $stmt = $pdo->prepare('SELECT ... WHERE id = :id'); $stmt->execute(['id' => $id]);).",
    rationale="Direct string concatenation in database queries is a primary source of web application compromise in PHP.",
)

RULE_PHP_002 = RuleDefinition(
    rule_id="ENT-PHP-002",
    category=DebtCategory.INPUT_VALIDATION,
    title="Unsafe Dynamic File Inclusion in PHP",
    description="Detects dynamic include/require statements containing request variables ($_GET, $_POST, $_REQUEST) or unvalidated file paths.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PHP],
    impact_template="Dynamic file inclusion allows Local File Inclusion (LFI) or Remote File Inclusion (RFI), enabling unauthorized file access or code execution.",
    recommendation_template="Avoid dynamic includes; use an explicit whitelist of allowed file names or rely on standard Composer PSR-4 class autoloading.",
    rationale="Dynamic file inclusions bypass static modularity and expose direct file access vulnerabilities.",
)

RULE_PHP_003 = RuleDefinition(
    rule_id="ENT-PHP-003",
    category=DebtCategory.INPUT_VALIDATION,
    title="Arbitrary Code or Command Execution in PHP",
    description="Detects calls to eval(), system(), exec(), shell_exec(), or passthru() in PHP applications.",
    default_severity=Severity.CRITICAL,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PHP],
    impact_template="eval() and shell execution functions allow execution of untrusted PHP code or operating system commands.",
    recommendation_template="Eliminate eval() entirely. If shell commands are required, strictly sanitize arguments with escapeshellarg() and escapeshellcmd().",
    rationale="Dynamic evaluation and shell invocation represent the highest severity class of code execution debt.",
)


def _strip_php_comments(line: str, in_block: bool) -> tuple[str, bool]:
    if in_block:
        if "*/" in line:
            _, after = line.split("*/", 1)
            rest, still_in = _strip_php_comments(after, False)
            return (" " * (len(line) - len(rest))) + rest, still_in
        return " " * len(line), True

    if "/*" in line:
        before, after = line.split("/*", 1)
        if "*/" in after:
            _, end_after = after.split("*/", 1)
            processed_end, _ = _strip_php_comments(end_after, False)
            return before + " " * (len(line) - len(before) - len(processed_end)) + processed_end, False
        return before + " " * (len(line) - len(before)), True

    # Line comments in PHP: // or #
    if "//" in line:
        before, _ = line.split("//", 1)
        return before, False
    if "#" in line:
        before, _ = line.split("#", 1)
        return before, False

    return line, False


def check_php_rules(file: ParsedFile) -> list[Finding]:
    """Analyze a PHP source file and return deterministic findings."""
    findings: list[Finding] = []
    in_block = False

    for idx, raw_line in enumerate(file.lines, start=1):
        clean_line, in_block = _strip_php_comments(raw_line, in_block)
        stripped = clean_line.strip()
        if not stripped:
            continue

        # 1. Check SQL injection
        is_php_sqli = False
        match_sql = PHP_SQL_REGEX.search(clean_line)
        if match_sql:
            args_str = match_sql.group(1).strip()
            # If arguments contain '.' concatenation or dynamic variables in SQL
            if ("." in args_str and ('"' in args_str or "'" in args_str)) or ("$" in args_str and '"' in args_str):
                is_php_sqli = True
        elif "." in clean_line and ("$" in clean_line) and ('"' in clean_line or "'" in clean_line):
            lower = clean_line.lower()
            if any(k in lower for k in ["select ", "insert into", "update ", "delete from"]):
                is_php_sqli = True

        if is_php_sqli:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_PHP_001.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="query",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_PHP_001.rule_id,
                file=file.relative_path,
                symbol="query",
                pattern_signature=f"php_sqli:{stripped}",
            )
            col_start = match_sql.start() if match_sql else (clean_line.find(".") if "." in clean_line else 0)
            col_end = match_sql.end() if match_sql else len(clean_line)
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_PHP_001.category,
                    rule_id=RULE_PHP_001.rule_id,
                    severity=RULE_PHP_001.default_severity,
                    confidence=RULE_PHP_001.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=col_start,
                    column_end=col_end,
                    symbol="query",
                    title="SQL Injection via String Concatenation in PHP",
                    description="Database query constructed with dynamic string concatenation ('.') or variable interpolation.",
                    evidence=evidence,
                    impact=RULE_PHP_001.impact_template,
                    recommendation=RULE_PHP_001.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.PHP,
                    reference="https://owasp.org/www-community/attacks/SQL_Injection",
                    metadata={"function": "query", "language": "php"},
                )
            )

        # 2. Check dynamic file inclusion
        match_inc = PHP_INCLUDE_REGEX.search(clean_line)
        if match_inc:
            stmt = match_inc.group(1)
            target = match_inc.group(2).strip()
            # Check if dynamic variables or request parameters are passed
            if ("$_GET" in target or "$_POST" in target or "$_REQUEST" in target or "$" in target) and not target.startswith(("__DIR__", "dirname(")):
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_PHP_002.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol=stmt,
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_PHP_002.rule_id,
                    file=file.relative_path,
                    symbol=stmt,
                    pattern_signature=f"php_lfi:{stmt}:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_PHP_002.category,
                        rule_id=RULE_PHP_002.rule_id,
                        severity=RULE_PHP_002.default_severity,
                        confidence=RULE_PHP_002.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match_inc.start(),
                        column_end=match_inc.end(),
                        symbol=stmt,
                        title=f"Unsafe Dynamic File Inclusion via {stmt} in PHP",
                        description=f"Dynamic path passed to '{stmt}' construct without a static path whitelist.",
                        evidence=evidence,
                        impact=RULE_PHP_002.impact_template,
                        recommendation=RULE_PHP_002.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.PHP,
                        reference="https://cwe.mitre.org/data/definitions/98.html",
                        metadata={"statement": stmt, "language": "php"},
                    )
                )

        # 3. Check code and command execution
        for match_exec in PHP_DANGEROUS_EXEC_REGEX.finditer(clean_line):
            fn_name = match_exec.group(1)
            col = match_exec.start()
            if col > 0 and clean_line[col - 1] in "_a-zA-Z0-9":
                continue
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_PHP_003.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol=fn_name,
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_PHP_003.rule_id,
                file=file.relative_path,
                symbol=fn_name,
                pattern_signature=f"php_exec:{fn_name}:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_PHP_003.category,
                    rule_id=RULE_PHP_003.rule_id,
                    severity=RULE_PHP_003.default_severity,
                    confidence=RULE_PHP_003.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=col,
                    column_end=match_exec.end(),
                    symbol=fn_name,
                    title=f"Arbitrary Code / Shell Execution via {fn_name}() in PHP",
                    description=f"Direct invocation of dangerous execution function '{fn_name}()'.",
                    evidence=evidence,
                    impact=RULE_PHP_003.impact_template,
                    recommendation=RULE_PHP_003.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.PHP,
                    reference="https://cwe.mitre.org/data/definitions/94.html",
                    metadata={"function": fn_name, "language": "php"},
                )
            )

    return findings
