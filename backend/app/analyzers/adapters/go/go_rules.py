"""Deterministic static analysis rules for Go language codebases."""

from __future__ import annotations

import re

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# Go SQL query methods: db.Query, db.QueryRow, db.Exec, tx.Query, etc.
GO_SQL_METHOD_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9_]+\.)?(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*([^)]+)\)",
    re.ASCII,
)

# Insecure TLS configuration: InsecureSkipVerify: true
GO_INSECURE_TLS_REGEX = re.compile(r"\bInsecureSkipVerify\s*:\s*true\b", re.ASCII)

# unsafe.Pointer usage
GO_UNSAFE_POINTER_REGEX = re.compile(r"\bunsafe\.Pointer\s*\(", re.ASCII)

# Command injection via exec.Command("sh", "-c", ...) or exec.Command("bash", "-c", ...)
GO_EXEC_CMD_REGEX = re.compile(
    r"\bexec\.Command\s*\(\s*\"(?:sh|bash|cmd|zsh)\"\s*,\s*\"-c\"\s*,\s*([^)]+)\)",
    re.ASCII,
)


RULE_GO_001 = RuleDefinition(
    rule_id="ENT-GO-001",
    category=DebtCategory.INPUT_VALIDATION,
    title="SQL Injection via String Formatting in Go",
    description="Detects SQL queries assembled using fmt.Sprintf() or string concatenation '+' in database/sql Query or Exec calls.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.GO],
    impact_template="Dynamic SQL query construction allows external input to alter query syntax, enabling unauthorized data access and extraction.",
    recommendation_template="Use parameterized query placeholders ($1, ?) provided by database/sql (e.g. db.Query(\"SELECT ... WHERE id = $1\", id)).",
    rationale="String-formatted SQL queries in Go represent critical input-validation architectural debt.",
)

RULE_GO_002 = RuleDefinition(
    rule_id="ENT-GO-002",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Insecure TLS Certificate Verification in Go",
    description="Detects tls.Config with InsecureSkipVerify set to true, completely disabling TLS certificate authentication.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.GO],
    impact_template="Disabling TLS validation exposes network communications to man-in-the-middle (MITM) attacks and credential theft.",
    recommendation_template="Remove InsecureSkipVerify: true or configure a custom x509.CertPool in tls.Config.RootCAs for self-signed development environments.",
    rationale="Disabling TLS certificate checks represents severe architectural security configuration debt.",
)

RULE_GO_003 = RuleDefinition(
    rule_id="ENT-GO-003",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Dangerous Memory Bypass via unsafe.Pointer in Go",
    description="Detects usage of unsafe.Pointer, which subverts Go's type system and garbage collector safety invariants.",
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.GO],
    impact_template="unsafe.Pointer bypasses Go's type-safety and memory protections, risking memory corruption or undefined runtime behavior.",
    recommendation_template="Use safe standard library conversions, reflect, or explicit copy mechanisms instead of unsafe.Pointer.",
    rationale="Direct pointer casting without safe abstractions represents architectural safety debt.",
)

RULE_GO_004 = RuleDefinition(
    rule_id="ENT-GO-004",
    category=DebtCategory.INPUT_VALIDATION,
    title="Command Injection via Shell Invocation in Go",
    description="Detects exec.Command invoking a shell interpreter (sh -c / bash -c) with dynamic string concatenation.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.GO],
    impact_template="Passing dynamic strings to a shell command interpreter allows execution of injected shell metacharacters and arbitrary commands.",
    recommendation_template="Invoke executables directly without the shell: pass the executable name and arguments as separate tokens in exec.Command().",
    rationale="Invoking the shell directly creates critical command-injection vulnerability risks.",
)


def _strip_go_comments(line: str, in_block: bool) -> tuple[str, bool]:
    if in_block:
        if "*/" in line:
            _, after = line.split("*/", 1)
            rest, still_in = _strip_go_comments(after, False)
            return (" " * (len(line) - len(rest))) + rest, still_in
        return " " * len(line), True

    if "/*" in line:
        before, after = line.split("/*", 1)
        if "*/" in after:
            _, end_after = after.split("*/", 1)
            processed_end, _ = _strip_go_comments(end_after, False)
            return before + " " * (len(line) - len(before) - len(processed_end)) + processed_end, False
        return before + " " * (len(line) - len(before)), True

    if "//" in line:
        before, _ = line.split("//", 1)
        return before, False

    return line, False


def check_go_rules(file: ParsedFile) -> list[Finding]:
    """Analyze a Go source file and return deterministic findings."""
    findings: list[Finding] = []
    in_block = False

    for idx, raw_line in enumerate(file.lines, start=1):
        clean_line, in_block = _strip_go_comments(raw_line, in_block)
        stripped = clean_line.strip()
        if not stripped:
            continue

        # 1. Check SQL injection via fmt.Sprintf or '+'
        is_go_sqli = False
        match_sql = GO_SQL_METHOD_REGEX.search(clean_line)
        if match_sql:
            args_str = match_sql.group(1).strip()
            if "fmt.Sprintf" in args_str or ("+" in args_str and ('"' in args_str or "query" in args_str.lower())):
                is_go_sqli = True
        elif "fmt.Sprintf" in clean_line and '"' in clean_line:
            lower = clean_line.lower()
            if any(k in lower for k in ["select ", "insert into", "update ", "delete from"]):
                is_go_sqli = True

        if is_go_sqli:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_GO_001.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="Query",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_GO_001.rule_id,
                file=file.relative_path,
                symbol="Query",
                pattern_signature=f"go_sqli:{stripped}",
            )
            col_start = match_sql.start() if match_sql else (clean_line.find("fmt.Sprintf") if "fmt.Sprintf" in clean_line else 0)
            col_end = match_sql.end() if match_sql else len(clean_line)
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_GO_001.category,
                    rule_id=RULE_GO_001.rule_id,
                    severity=RULE_GO_001.default_severity,
                    confidence=RULE_GO_001.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=col_start,
                    column_end=col_end,
                    symbol="Query",
                    title="SQL Injection via Dynamic String in Go",
                    description="Query constructed using dynamic string formatting/concatenation passed to database query method.",
                    evidence=evidence,
                    impact=RULE_GO_001.impact_template,
                    recommendation=RULE_GO_001.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.GO,
                    reference="https://owasp.org/www-community/attacks/SQL_Injection",
                    metadata={"function": "Query", "language": "go"},
                )
            )

        # 2. Check InsecureSkipVerify: true
        match_tls = GO_INSECURE_TLS_REGEX.search(clean_line)
        if match_tls:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_GO_002.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="tls.Config",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_GO_002.rule_id,
                file=file.relative_path,
                symbol="tls.Config",
                pattern_signature=f"go_insecure_tls:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_GO_002.category,
                    rule_id=RULE_GO_002.rule_id,
                    severity=RULE_GO_002.default_severity,
                    confidence=RULE_GO_002.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=match_tls.start(),
                    column_end=match_tls.end(),
                    symbol="InsecureSkipVerify",
                    title="Insecure TLS Verification in Go",
                    description="InsecureSkipVerify: true observed, disabling TLS certificate authentication.",
                    evidence=evidence,
                    impact=RULE_GO_002.impact_template,
                    recommendation=RULE_GO_002.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.GO,
                    reference="https://cwe.mitre.org/data/definitions/295.html",
                    metadata={"setting": "InsecureSkipVerify", "language": "go"},
                )
            )

        # 3. Check unsafe.Pointer
        match_ptr = GO_UNSAFE_POINTER_REGEX.search(clean_line)
        if match_ptr:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_GO_003.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="unsafe.Pointer",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_GO_003.rule_id,
                file=file.relative_path,
                symbol="unsafe.Pointer",
                pattern_signature=f"go_unsafe_ptr:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_GO_003.category,
                    rule_id=RULE_GO_003.rule_id,
                    severity=RULE_GO_003.default_severity,
                    confidence=RULE_GO_003.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=match_ptr.start(),
                    column_end=match_ptr.end(),
                    symbol="unsafe.Pointer",
                    title="Memory Bypass via unsafe.Pointer in Go",
                    description="Direct pointer conversion using 'unsafe.Pointer' observed.",
                    evidence=evidence,
                    impact=RULE_GO_003.impact_template,
                    recommendation=RULE_GO_003.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.GO,
                    reference="https://pkg.go.dev/unsafe#Pointer",
                    metadata={"package": "unsafe", "language": "go"},
                )
            )

        # 4. Check exec.Command with shell invocation
        match_exec = GO_EXEC_CMD_REGEX.search(clean_line)
        if match_exec:
            args_content = match_exec.group(1).strip()
            if args_content and not (args_content.startswith('"') and args_content.endswith('"') and "+" not in args_content):
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_GO_004.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol="exec.Command",
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_GO_004.rule_id,
                    file=file.relative_path,
                    symbol="exec.Command",
                    pattern_signature=f"go_shell_exec:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_GO_004.category,
                        rule_id=RULE_GO_004.rule_id,
                        severity=RULE_GO_004.default_severity,
                        confidence=RULE_GO_004.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match_exec.start(),
                        column_end=match_exec.end(),
                        symbol="exec.Command",
                        title="Command Injection via Shell Execution in Go",
                        description="Passing dynamically formatted strings to a shell command runner in exec.Command().",
                        evidence=evidence,
                        impact=RULE_GO_004.impact_template,
                        recommendation=RULE_GO_004.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.GO,
                        reference="https://cwe.mitre.org/data/definitions/78.html",
                        metadata={"function": "exec.Command", "language": "go"},
                    )
                )

    return findings
