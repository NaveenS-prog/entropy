"""Deterministic static analysis rules for C++ language codebases."""

from __future__ import annotations

import re

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# Raw memory management in C++
# Matches standalone `new ` or `delete ` or `delete[]` but not `placement new` or operator overloading
CPP_RAW_NEW_REGEX = re.compile(r"\bnew\s+(?:(?!\()[a-zA-Z0-9_:]+)(?:\[|\s*\{|\s*\()", re.ASCII)
CPP_RAW_DELETE_REGEX = re.compile(r"\bdelete(?:\s*\[\]|\s+)[a-zA-Z0-9_]+", re.ASCII)

# reinterpret_cast
REINTERPRET_CAST_REGEX = re.compile(r"\breinterpret_cast\s*<", re.ASCII)

# C-style unsafe string APIs in C++
CPP_LEGACY_BUFFER_REGEX = re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(", re.ASCII)


RULE_CPP_001 = RuleDefinition(
    rule_id="ENT-CPP-001",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Unmanaged Raw Memory Allocation in Modern C++",
    description="Detects direct use of raw 'new' or 'delete' operators in modern C++ instead of RAII containers or smart pointers.",
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.CPP],
    impact_template="Raw pointer memory management bypasses RAII exception guarantees, leading to memory leaks, double-frees, or use-after-free defects.",
    recommendation_template="Use modern C++ smart pointers (std::unique_ptr, std::shared_ptr, std::make_unique) or RAII containers (std::vector, std::string).",
    rationale="Managing heap memory manually in modern C++ represents architectural memory-safety debt.",
)

RULE_CPP_002 = RuleDefinition(
    rule_id="ENT-CPP-002",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Dangerous Type Punning via reinterpret_cast in C++",
    description="Detects reinterpret_cast operations in C++, which subvert the type system and risk strict-aliasing violations or undefined memory layout assumptions.",
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.CPP],
    impact_template="reinterpret_cast bypasses compiler type safety and is prone to undefined behavior when object layouts or alignment differ.",
    recommendation_template="Use static_cast, std::bit_cast (C++20), or safe polymorphic abstractions instead of reinterpret_cast.",
    rationale="Arbitrary type-casting is an indicator of architectural type-safety debt in C++.",
)

RULE_CPP_003 = RuleDefinition(
    rule_id="ENT-CPP-003",
    category=DebtCategory.INPUT_VALIDATION,
    title="Legacy Unsafe C Buffer Function in C++ Source",
    description="Detects unsafe C string functions (strcpy, strcat, sprintf, gets) in C++ source files where safe C++ abstractions exist.",
    default_severity=Severity.HIGH,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.CPP],
    impact_template="C-style buffer operations lack bounds verification and can overflow destination buffers.",
    recommendation_template="Use std::string, std::string_view, std::format, or snprintf instead of legacy unbounded C functions.",
    rationale="Mixing unbounded C string functions into C++ undermines modern C++ memory safety guarantees.",
)


def _strip_comments(line: str, in_block: bool) -> tuple[str, bool]:
    if in_block:
        if "*/" in line:
            _, after = line.split("*/", 1)
            rest, still_in = _strip_comments(after, False)
            return (" " * (len(line) - len(rest))) + rest, still_in
        return " " * len(line), True

    if "/*" in line:
        before, after = line.split("/*", 1)
        if "*/" in after:
            _, end_after = after.split("*/", 1)
            processed_end, _ = _strip_comments(end_after, False)
            return before + " " * (len(line) - len(before) - len(processed_end)) + processed_end, False
        return before + " " * (len(line) - len(before)), True

    if "//" in line:
        before, _ = line.split("//", 1)
        return before, False

    return line, False


def check_cpp_rules(file: ParsedFile) -> list[Finding]:
    """Analyze a C++ source file and return deterministic findings."""
    findings: list[Finding] = []
    in_block = False

    for idx, raw_line in enumerate(file.lines, start=1):
        clean_line, in_block = _strip_comments(raw_line, in_block)
        stripped = clean_line.strip()
        if not stripped:
            continue

        # 1. Check raw new/delete
        # Avoid placement new e.g. new (ptr) Type
        if ("new " in clean_line or "delete " in clean_line or "delete[]" in clean_line) and "operator new" not in clean_line and "operator delete" not in clean_line:
            match_new = CPP_RAW_NEW_REGEX.search(clean_line)
            match_del = CPP_RAW_DELETE_REGEX.search(clean_line)
            match = match_new or match_del
            if match and "std::make_" not in clean_line:
                op_type = "new" if match_new else "delete"
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_CPP_001.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol=op_type,
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_CPP_001.rule_id,
                    file=file.relative_path,
                    symbol=op_type,
                    pattern_signature=f"raw_memory:{op_type}:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_CPP_001.category,
                        rule_id=RULE_CPP_001.rule_id,
                        severity=RULE_CPP_001.default_severity,
                        confidence=RULE_CPP_001.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match.start(),
                        column_end=match.end(),
                        symbol=op_type,
                        title=f"Raw Memory Operator '{op_type}' in Modern C++",
                        description=f"Direct heap memory management using '{op_type}' observed without RAII smart pointer encapsulation.",
                        evidence=evidence,
                        impact=RULE_CPP_001.impact_template,
                        recommendation=RULE_CPP_001.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.CPP,
                        reference="https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Rr-newdrop",
                        metadata={"operator": op_type, "language": "cpp"},
                    )
                )

        # 2. Check reinterpret_cast
        for match in REINTERPRET_CAST_REGEX.finditer(clean_line):
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_CPP_002.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="reinterpret_cast",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_CPP_002.rule_id,
                file=file.relative_path,
                symbol="reinterpret_cast",
                pattern_signature=f"reinterpret_cast:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_CPP_002.category,
                    rule_id=RULE_CPP_002.rule_id,
                    severity=RULE_CPP_002.default_severity,
                    confidence=RULE_CPP_002.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=match.start(),
                    column_end=match.end(),
                    symbol="reinterpret_cast",
                    title="Dangerous reinterpret_cast in C++",
                    description="Use of 'reinterpret_cast' subverts type safety and risks undefined behavior.",
                    evidence=evidence,
                    impact=RULE_CPP_002.impact_template,
                    recommendation=RULE_CPP_002.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.CPP,
                    reference="https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Res-casts-reinterpret",
                    metadata={"cast": "reinterpret_cast", "language": "cpp"},
                )
            )

        # 3. Check legacy C buffer operations in C++
        for match in CPP_LEGACY_BUFFER_REGEX.finditer(clean_line):
            fn_name = match.group(1)
            col = match.start()
            if col > 0 and clean_line[col - 1] in "_a-zA-Z0-9":
                continue
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_CPP_003.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol=fn_name,
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_CPP_003.rule_id,
                file=file.relative_path,
                symbol=fn_name,
                pattern_signature=f"legacy_c_buf:{fn_name}:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_CPP_003.category,
                    rule_id=RULE_CPP_003.rule_id,
                    severity=RULE_CPP_003.default_severity,
                    confidence=RULE_CPP_003.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=col,
                    column_end=match.end(),
                    symbol=fn_name,
                    title=f"Legacy C Buffer Function '{fn_name}()' in C++",
                    description=f"Use of legacy C string function '{fn_name}()' in C++ code where safe std::string or std::format should be used.",
                    evidence=evidence,
                    impact=RULE_CPP_003.impact_template,
                    recommendation=RULE_CPP_003.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.CPP,
                    reference="https://cwe.mitre.org/data/definitions/120.html",
                    metadata={"function": fn_name, "language": "cpp"},
                )
            )

    return findings
